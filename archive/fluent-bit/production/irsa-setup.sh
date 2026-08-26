#!/usr/bin/env bash
# One-shot bootstrap: S3 bucket (hardened + lifecycle) and least-privilege IAM
# role for Fluent Bit via IRSA on EKS.
#
# Usage:
#   export CLUSTER_NAME=my-prod-cluster AWS_REGION=ap-south-1 S3_BUCKET=myco-k8s-logs
#   ./irsa-setup.sh
# Optional env: NAMESPACE (default kube-system), SA_NAME (default fluent-bit-s3)
#
# At the end it prints the eks.amazonaws.com/role-arn to paste into helm-values.yaml.
set -euo pipefail

: "${CLUSTER_NAME:?export CLUSTER_NAME=<eks-cluster>}"
: "${AWS_REGION:?export AWS_REGION=<region>}"
: "${S3_BUCKET:?export S3_BUCKET=<bucket>}"
NAMESPACE="${NAMESPACE:-kube-system}"
SA_NAME="${SA_NAME:-fluent-bit-s3}"

command -v aws >/dev/null || { echo "aws CLI required"; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
OIDC_HOST=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" \
  --query cluster.identity.oidc.issuer --output text | sed 's|https://||')
OIDC_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_HOST}"
ROLE_NAME="fluent-bit-s3-logs-${CLUSTER_NAME}"

echo "== Registering OIDC provider (idempotent) =="
aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC_ARN" >/dev/null 2>&1 || \
  aws iam create-open-id-connect-provider \
    --url "https://${OIDC_HOST}" \
    --client-id-list sts.amazonaws.com \
    --thumbprint-list "9E99A48A9960B14926BB7F3B02E07DA36F4D80A0"

echo "== Creating bucket s3://${S3_BUCKET} (if absent) + hardening =="
if ! aws s3api head-bucket --bucket "$S3_BUCKET" 2>/dev/null; then
  if [ "$AWS_REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$S3_BUCKET"
  else
    aws s3api create-bucket --bucket "$S3_BUCKET" \
      --create-bucket-configuration LocationConstraint="$AWS_REGION"
  fi
fi
aws s3api put-public-access-block --bucket "$S3_BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-versioning --bucket "$S3_BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket "$S3_BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-bucket-lifecycle-configuration --bucket "$S3_BUCKET" \
  --lifecycle-configuration '{"Rules":[{"ID":"log-tiering","Filter":{"Prefix":"cluster-logs/"},
  "Status":"Enabled","Transitions":[{"Days":30,"StorageClass":"INTELLIGENT_TIERING"},
  {"Days":90,"StorageClass":"GLACIER_IR"}],"Expiration":{"Days":365}}]}'

echo "== Creating IAM policy + role ${ROLE_NAME} =="
cat > /tmp/flb-s3-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "WriteClusterLogs",
    "Effect": "Allow",
    "Action": ["s3:PutObject", "s3:AbortMultipartUpload"],
    "Resource": ["arn:aws:s3:::${S3_BUCKET}/cluster-logs/*"]
  }]
}
EOF
POLICY_NAME="${ROLE_NAME}-policy"
POLICY_ARN=$(aws iam list-policies --scope Local --query \
  "Policies[?PolicyName=='${POLICY_NAME}'].Arn" --output text | head -n1)
if [ -z "$POLICY_ARN" ] || [ "$POLICY_ARN" = "None" ]; then
  POLICY_ARN=$(aws iam create-policy --policy-name "$POLICY_NAME" \
    --policy-document file:///tmp/flb-s3-policy.json --query Policy.Arn --output text)
fi

cat > /tmp/flb-s3-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "${OIDC_ARN}"},
    "Action": ["sts:AssumeRole", "sts:TagSession"],
    "Condition": {
      "StringEquals": {"${OIDC_HOST}:sub": "system:serviceaccount:${NAMESPACE}:${SA_NAME}"}
    }
  }]
}
EOF
aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1 || \
  aws iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document file:///tmp/flb-s3-trust.json >/dev/null
aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN"

cat <<DONE

============================================================
 DONE. Paste this into production/helm-values.yaml:

serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}

(keep SA name '${SA_NAME}' and namespace '${NAMESPACE}')
============================================================
DONE