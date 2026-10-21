# Logscope: single PyInstaller binary on a distroless runtime (no shell, no
# package manager). Build through the Makefile, which passes VERSION:
#
#   make image                       # current arch, --load
#   make image-multi PUSH=1          # linux/amd64 + linux/arm64, pushed
#   make bin                         # onefile binary into dist/
#   make deps-lock                   # regenerate requirements*.lock
#
# Base images are pinned by multi-arch index digest. To refresh:
#   docker buildx imagetools inspect python:3.12-slim-bookworm --format '{{json .Manifest.Digest}}'
#   docker buildx imagetools inspect gcr.io/distroless/cc-debian12 --format '{{json .Manifest.Digest}}'
# Builder and runtime must stay on the same Debian release (bookworm / debian12):
# the bundle uses the runtime's glibc.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12@sha256:e5d81ddde149641e2a9ba55be4545bc125c67de07508b03ba4c22e6eb0ded5aa

# ---------------------------------------------------------------------------
# lock: `make deps-lock` regenerates requirements.lock / requirements-build.lock.
# pip-tools is installed only here, never in the builder or runtime image.
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS lock
ARG PIP_TOOLS_VERSION=7.6.2
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore \
    CUSTOM_COMPILE_COMMAND="make deps-lock"
RUN pip install "pip-tools==${PIP_TOOLS_VERSION}"
WORKDIR /src
COPY requirements.txt requirements.in requirements-build.in ./
COPY webapp/requirements.txt webapp/requirements.txt
RUN pip-compile --quiet --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url \
        --output-file requirements.lock requirements.in \
    && pip-compile --quiet --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url \
        --output-file requirements-build.lock requirements-build.in \
    && mkdir /out && cp requirements.lock requirements-build.lock /out/

FROM scratch AS lockfiles
COPY --from=lock /out/ /

# ---------------------------------------------------------------------------
# builder: hash-checked install, then PyInstaller (onedir for the image).
# Runs on the target platform: PyInstaller cannot cross-compile (arm64 builds
# use QEMU via buildx, or a native arm64 runner).
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1
# binutils: objdump/strip for PyInstaller (strip=True). UPX is not installed,
# so the spec skips it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends binutils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY requirements.lock requirements-build.lock ./
RUN pip install --require-hashes --no-deps -r requirements.lock -r requirements-build.lock \
    && pip check
COPY config.example.yaml ./
COPY packaging/ packaging/
COPY webapp/ webapp/
COPY logscope/ logscope/
ARG VERSION=0.0.0+unknown
ARG REVISION=
RUN python packaging/write_version.py "${VERSION}" "${REVISION}" \
    && python -m PyInstaller --noconfirm --clean --log-level WARN \
        --distpath /dist --workpath /tmp/pyi-onedir packaging/logscope.spec \
    && python packaging/check_bundle.py /dist/logscope \
    && /dist/logscope/logscope version
# Root filesystem overlay for the runtime image (distroless has no shell to
# create the symlink there). The PyInstaller bootloader links libz.so.1 before
# it can load the bundled copy, and distroless/cc has no zlib: add Debian
# bookworm's zlib1g library (same release as debian12) plus its dpkg status
# entry, so image scanners and SBOMs still see and track the package.
RUN multiarch="$(python -c 'import sysconfig; print(sysconfig.get_config_var("MULTIARCH"))')" \
    && mkdir -p /rootfs/opt /rootfs/usr/local/bin /rootfs/etc/logscope /rootfs-data/data \
        "/rootfs/usr/lib/${multiarch}" /rootfs/var/lib/dpkg/status.d \
    && cp -a /dist/logscope /rootfs/opt/logscope \
    && ln -s /opt/logscope/logscope /rootfs/usr/local/bin/logscope \
    && cp -L "/usr/lib/${multiarch}/libz.so.1" "/rootfs/usr/lib/${multiarch}/libz.so.1" \
    && dpkg-query -s zlib1g > /rootfs/var/lib/dpkg/status.d/zlib1g

# ---------------------------------------------------------------------------
# onefile: standalone binary (`make bin` exports it through the `bin` stage).
# ---------------------------------------------------------------------------
FROM builder AS onefile
RUN LOGSCOPE_ONEFILE=1 python -m PyInstaller --noconfirm --clean --log-level WARN \
        --distpath /dist-onefile --workpath /tmp/pyi-onefile packaging/logscope.spec \
    && python packaging/check_bundle.py --onefile /dist-onefile/logscope \
    && /dist-onefile/logscope version

FROM scratch AS bin
COPY --from=onefile /dist-onefile/logscope /logscope

# ---------------------------------------------------------------------------
# kubectl (optional): INCLUDE_KUBECTL=true adds a pinned, sha256-verified
# kubectl for clusters that enable actions (they also need an explicit RBAC
# Role; see the Helm chart's kubectl.* / rbac.* values). Default: none.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${PYTHON_IMAGE} AS kubectl
ARG TARGETARCH
ARG INCLUDE_KUBECTL=false
ARG KUBECTL_VERSION=v1.37.1
ARG KUBECTL_SHA256_AMD64=65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8
ARG KUBECTL_SHA256_ARM64=ff749f4b78d9c4f1ec87307df9b50119ed819e2094aa9810cb9acffc3286c8c7
COPY packaging/fetch_kubectl.py /fetch_kubectl.py
RUN mkdir -p /out/usr/local/bin \
    && if [ "${INCLUDE_KUBECTL}" = "true" ]; then \
         case "${TARGETARCH}" in \
           amd64) sum="${KUBECTL_SHA256_AMD64}" ;; \
           arm64) sum="${KUBECTL_SHA256_ARM64}" ;; \
           *) echo "no pinned kubectl checksum for ${TARGETARCH}" >&2; exit 1 ;; \
         esac; \
         python /fetch_kubectl.py "${KUBECTL_VERSION}" "${TARGETARCH}" "${sum}" /out/usr/local/bin/kubectl; \
       elif [ "${INCLUDE_KUBECTL}" != "false" ]; then \
         echo "INCLUDE_KUBECTL must be true or false" >&2; exit 1; \
       fi

# ---------------------------------------------------------------------------
# runtime
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime
ARG VERSION=0.0.0+unknown
ARG REVISION=
ARG CREATED=
ARG SOURCE=
LABEL org.opencontainers.image.title="logscope" \
      org.opencontainers.image.description="Logscope web app: Kubernetes log viewer with anomaly insights" \
      org.opencontainers.image.licenses="NOASSERTION" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.created="${CREATED}"
COPY --from=builder /rootfs/ /
# /data: default database location; a fresh named volume inherits the owner.
COPY --from=builder --chown=10001:10001 /rootfs-data/data /data
COPY --from=kubectl /out/ /
# TMPDIR: SQLite temp files (an emptyDir under a read-only root filesystem).
# SSL_CERT_FILE: the bundled OpenSSL uses the distroless CA bundle.
# XDG_DATA_HOME: UID 10001 has no home directory here, so the default state
# database (saved views) lands in /data/logscope/ unless config or
# LOGSCOPE_WEBAPP_STATE_DB_PATH (set by the Helm chart) says otherwise.
ENV TMPDIR=/tmp \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    XDG_DATA_HOME=/data
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=6s --start-period=60s --retries=3 CMD ["logscope", "healthcheck"]
ENTRYPOINT ["logscope"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000", "--config", "/etc/logscope/config.yaml"]
