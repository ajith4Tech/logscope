#!/usr/bin/env bash
# Smoke test for the Logscope image and onefile binary. Builds both (unless
# SKIP_BUILD=1), runs the image the way the Helm chart does (read-only root,
# tmpfs /tmp, UID 10001, state on a volume) with S3 configured but unreachable
# and AI disabled, then checks the binary directly. Never pushes and never
# contacts AWS: S3 points at a closed local port.
#
#   scripts/smoke.sh                     # or: make smoke
#   SKIP_BUILD=1 IMAGE=... TAG=... BIN=... scripts/smoke.sh
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(make -s version)}"
IMAGE="${IMAGE:-ghcr.io/ajith4tech/logscope}"
TAG="${TAG:-$(echo "${VERSION#v}" | tr '+' '-')}"
ARCH="${ARCH:-$(uname -m | sed -e s/x86_64/amd64/ -e s/aarch64/arm64/)}"
BIN="${BIN:-dist/logscope-${VERSION}-linux-${ARCH}}"
REF="${IMAGE}:${TAG}"

failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }
info() { printf 'INFO  %s\n' "$*"; }
check() { local name="$1"; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    make image bin VERSION="${VERSION}" IMAGE="${IMAGE}" TAG="${TAG}" ARCH="${ARCH}"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/logscope-smoke.XXXXXX")"
volume="logscope-smoke-$$"
config_volume="logscope-smoke-config-$$"
cid=""
loader=""
bin_pid=""
cleanup() {
    [[ -n "${bin_pid}" ]] && kill "${bin_pid}" 2>/dev/null || true
    [[ -n "${cid}" ]] && docker rm -f "${cid}" >/dev/null 2>&1 || true
    [[ -n "${loader}" ]] && docker rm -f "${loader}" >/dev/null 2>&1 || true
    docker volume rm -f "${volume}" "${config_volume}" >/dev/null 2>&1 || true
    rm -rf "${work}"
}
trap cleanup EXIT

# Config: S3 configured but unreachable (endpoint on a closed port), AI off.
mkdir -p "${work}/etc" "${work}/bin-data"
python3 - "${work}" <<'EOF'
import sys
import yaml
work = sys.argv[1]
cfg = yaml.safe_load(open("config.example.yaml"))
cfg["sinks"]["s3"].update(enabled=True, bucket="logscope-smoke-bucket", region="us-east-1")
cfg["webapp"]["ai"] = {"provider": "none", "model": ""}
cfg["webapp"]["backend"]["poll_interval_secs"] = 5
with open(f"{work}/etc/config.yaml", "w") as fh:
    yaml.safe_dump(cfg, fh)
# Same settings for the binary, with its databases in the temp directory.
cfg["webapp"]["backend"].update(db_path=f"{work}/bin-data/logscope.sqlite",
                                state_db_path=f"{work}/bin-data/state.sqlite")
with open(f"{work}/bin-config.yaml", "w") as fh:
    yaml.safe_dump(cfg, fh)
EOF
chmod 0755 "${work}" "${work}/etc"
chmod 0644 "${work}/etc/config.yaml"

wait_http() {  # url, attempts
    local i
    for ((i = 0; i < ${2:-60}; i++)); do
        curl -fsS -o /dev/null "$1" 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

echo "== image ${REF}"
# The chart runs with allowPrivilegeEscalation: false (no_new_privs). Some
# hosts cannot exec anything under it (e.g. the snap-packaged Docker's
# AppArmor profile); that is reported, and only an image-specific failure fails.
nnp=(--security-opt no-new-privileges)
if ! docker run --rm "${nnp[@]}" "${REF}" version >/dev/null 2>&1; then
    base_image="$(sed -n 's/^ARG PYTHON_IMAGE=//p' Dockerfile)"
    if docker run --rm "${nnp[@]}" "${base_image}" python -c pass >/dev/null 2>&1; then
        fail "image cannot exec under no-new-privileges (the pinned Python base image can)"
    else
        info "this Docker host cannot exec any image under no-new-privileges (base image fails too); running without it"
    fi
    nnp=()
else
    pass "runs under no-new-privileges"
fi
docker volume create "${volume}" >/dev/null
# The config goes in through a volume (docker cp into a container that is
# never started) as a tar stream, not a bind mount: works with remote daemons
# and with snap-packaged Docker, which cannot see the host's /tmp.
docker volume create "${config_volume}" >/dev/null
loader="$(docker create -v "${config_volume}:/etc/logscope" "${REF}" version)"
tar -C "${work}/etc" -cf - config.yaml | docker cp - "${loader}:/etc/logscope" >/dev/null
docker rm "${loader}" >/dev/null; loader=""
s3_env=(-e AWS_ACCESS_KEY_ID=smoke-not-a-key -e AWS_SECRET_ACCESS_KEY=smoke-not-a-secret
        -e AWS_ENDPOINT_URL_S3=http://127.0.0.1:9 -e AWS_MAX_ATTEMPTS=1)
cid="$(docker run -d --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --cap-drop ALL "${nnp[@]}" \
    -v "${config_volume}:/etc/logscope:ro" -v "${volume}:/data" \
    -e LOGSCOPE_WEBAPP_DB_PATH=/data/logscope.sqlite \
    -e LOGSCOPE_WEBAPP_STATE_DB_PATH=/data/state/state.sqlite \
    "${s3_env[@]}" -p 127.0.0.1::8000 "${REF}")"
port="$(docker port "${cid}" 8000/tcp | head -1 | sed 's/.*://')"
base="http://127.0.0.1:${port}"

if wait_http "${base}/healthz" 120; then
    pass "/healthz returns 200"
else
    fail "/healthz did not return 200"; docker logs "${cid}" 2>&1 | tail -20
fi
index="$(curl -fsS "${base}/" || true)"
check "/ serves the UI" grep -q '<script src="/app.js"' <<<"${index}"
check "/app.js loads (JavaScript, 200)" bash -c \
    "curl -fsS -o /dev/null -w '%{http_code} %{content_type}' '${base}/app.js' | grep -q '^200 application/javascript'"
check "/styles.css loads" curl -fsS -o /dev/null "${base}/styles.css"
status_json="$(curl -fsS "${base}/api/status" || true)"
check "/api/status shows version ${VERSION}" grep -q "\"version\":\"${VERSION}\"" <<<"${status_json}"
check "X-Logscope-Version header" bash -c \
    "curl -fsS -D - -o /dev/null '${base}/healthz' | tr -d '\r' | grep -qx 'X-Logscope-Version: ${VERSION}'"
readyz="$(curl -sS -o /dev/null -w '%{http_code}' "${base}/readyz" || true)"
sleep 6  # let one ingest poll fail against the closed S3 endpoint
ingest="$(curl -fsS "${base}/api/status" | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["ingest"]["state"], "|", (s.get("last_error") or "")[:100])' || true)"
info "/readyz with S3 unreachable: HTTP ${readyz} (readiness tracks the local cache only); ingest: ${ingest}"

selfcheck="$(docker run --rm --read-only --tmpfs /tmp -v "${config_volume}:/etc/logscope:ro" -v "${volume}:/data" \
    -e LOGSCOPE_WEBAPP_DB_PATH=/data/logscope.sqlite -e LOGSCOPE_WEBAPP_STATE_DB_PATH=/data/state/state.sqlite \
    "${s3_env[@]}" "${REF}" selfcheck 2>&1 || true)"
check "selfcheck passes (FTS5)" bash -c 'grep -q "^ok    fts5" <<<"$1" && grep -q "selfcheck: passed" <<<"$1"' _ "${selfcheck}"
check "selfcheck: cryptography Fernet round-trip" grep -q "^ok    cryptography .*Fernet round-trip ok" <<<"${selfcheck}"
check "image healthcheck command" docker exec "${cid}" logscope healthcheck
uid="$(docker top "${cid}" -eo pid,uid,comm | awk 'NR > 1 && $3 == "logscope" {print $2; exit}' || true)"
check "runs as UID 10001 (process uid ${uid:-?}, image user $(docker inspect -f '{{.Config.User}}' "${REF}"))" \
    test "${uid}" = "10001" -a "$(docker inspect -f '{{.Config.User}}' "${REF}")" = "10001:10001"
check "no shell (docker exec sh fails)" bash -c "! docker exec '${cid}' sh -c true >/dev/null 2>&1 && ! docker exec '${cid}' /bin/sh -c true >/dev/null 2>&1"

# Secret / operator paths must not exist anywhere in the image filesystem.
listing="$(docker export "${cid}" | tar -t)"
leaks="$(grep -E '(^|/)config\.yaml$|secret[^/]*\.ya?ml$|\.sqlite|(^|/)\.git/|(^|/)\.state/|(^|/)\.venv/|^(opt/logscope/_internal/)?(logs|backups|archive|test|deploy|scripts)/|\.env$' <<<"${listing}" \
    | grep -v '^data/' || true)"
check "image contains none of the secret/operator paths" test -z "${leaks}"
[[ -n "${leaks}" ]] && printf '      %s\n' ${leaks}
docker rm -f "${cid}" >/dev/null; cid=""

echo "== binary ${BIN}"
if [[ ! -x "${BIN}" ]]; then
    fail "binary ${BIN} not found"
else
    check "binary version" bash -c "'${BIN}' version | grep -q '^logscope ${VERSION}'"
    out="$(AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y "${BIN}" selfcheck --config "${work}/bin-config.yaml" 2>&1 || true)"
    check "binary selfcheck passes (FTS5)" bash -c 'grep -q "^ok    fts5" <<<"$1" && grep -q "selfcheck: passed" <<<"$1"' _ "${out}"
    check "binary selfcheck: cryptography Fernet round-trip" grep -q "^ok    cryptography .*Fernet round-trip ok" <<<"${out}"
    bin_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
    AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_ENDPOINT_URL_S3=http://127.0.0.1:9 AWS_MAX_ATTEMPTS=1 \
        "${BIN}" serve --host 127.0.0.1 --port "${bin_port}" --config "${work}/bin-config.yaml" \
        >"${work}/bin.log" 2>&1 &
    bin_pid=$!
    if wait_http "http://127.0.0.1:${bin_port}/healthz" 120; then
        pass "binary serve: curl /healthz returns 200"
    else
        fail "binary serve: /healthz did not return 200"; tail -20 "${work}/bin.log"
    fi
    check "binary serve: / serves the UI" bash -c "curl -fsS 'http://127.0.0.1:${bin_port}/' | grep -q '<script src=\"/app.js\"'"
    check "binary healthcheck command" env PORT="${bin_port}" "${BIN}" healthcheck
    kill -TERM "${bin_pid}"; wait "${bin_pid}" 2>/dev/null || true; bin_pid=""
    info "binary size: $(du -h "${BIN}" | cut -f1)"
fi
size="$(docker image inspect -f '{{.Size}}' "${REF}")"
info "image size: $(awk -v s="${size}" 'BEGIN {printf "%.1f MB", s/1e6}')"
# BASELINE_REF (e.g. the previous release's image) reports the size change.
if [[ -n "${BASELINE_REF:-}" ]] && base_size="$(docker image inspect -f '{{.Size}}' "${BASELINE_REF}" 2>/dev/null)"; then
    info "image size vs ${BASELINE_REF}: $(awk -v a="${size}" -v b="${base_size}" \
        'BEGIN {printf "%+.1f MB (%.1f MB -> %.1f MB, %+.1f%%)", (a-b)/1e6, b/1e6, a/1e6, 100*(a-b)/b}')"
fi

echo
if ((failures)); then echo "smoke: ${failures} check(s) FAILED"; exit 1; fi
echo "smoke: all checks passed"
