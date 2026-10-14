# Logscope web app (API + static UI). Build from the repo root:
#   docker build -f webapp/Dockerfile -t logscope-webapp:$(git rev-parse --short HEAD) .
#
# Base image pinned by digest for reproducible builds. To refresh:
#   docker pull python:3.12-slim-trixie
#   docker image inspect python:3.12-slim-trixie --format '{{index .RepoDigests 0}}'
FROM python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY webapp/requirements.txt webapp/requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore -r webapp/requirements.txt

COPY webapp/ webapp/
RUN python -m compileall -q webapp \
    && useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin logscope \
    && mkdir -p /data /etc/logscope \
    && chown 10001:10001 /data

USER 10001:10001
EXPOSE 8000

# Python is PID 1 and handles SIGTERM itself (graceful shutdown in server.main).
ENTRYPOINT ["python", "-m", "webapp.api.server"]
CMD ["--host", "0.0.0.0", "--port", "8000", "--config", "/etc/logscope/config.yaml"]
