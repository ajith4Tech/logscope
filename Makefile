# Logscope build targets. Nothing here pushes unless PUSH=1 is given to
# image-multi, and nothing touches a cluster (k3s-import only prints commands).
#
#   make test                 pytest
#   make render               generate deploy/*.yaml from config.yaml (gitignored)
#   make bin                  onefile binary -> dist/logscope-<version>-linux-<arch>
#   make image                container image for this machine's arch (--load)
#   make smoke                build image + binary, run scripts/smoke.sh
#   make image-multi PUSH=1   linux/amd64 + linux/arm64, pushed with SBOM + provenance
#   make k3s-import           print the commands to import the image into k3s
#   make sbom / make scan     SBOM + provenance / trivy scan
#   make deps-lock            regenerate requirements.lock + requirements-build.lock

SHELL := /bin/bash
.DEFAULT_GOAL := help

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0+unknown)
REVISION  ?= $(shell git rev-parse HEAD 2>/dev/null)
CREATED   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
SOURCE    ?= https://github.com/ajith4Tech/logscope
IMAGE     ?= ghcr.io/ajith4tech/logscope
# Image tag: VERSION without a leading "v" ("+" is not allowed in tags).
TAG       ?= $(subst +,-,$(patsubst v%,%,$(VERSION)))
ARCH      ?= $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
PLATFORMS ?= linux/amd64,linux/arm64
INCLUDE_KUBECTL ?= false
PYTHON    ?= python3
PUSH      ?= 0
DIST      ?= dist
BIN        = $(DIST)/logscope-$(VERSION)-linux-$(ARCH)

BUILD_ARGS = --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) \
             --build-arg CREATED=$(CREATED) --build-arg SOURCE=$(SOURCE) \
             --build-arg INCLUDE_KUBECTL=$(INCLUDE_KUBECTL)

.PHONY: help deps-lock test render bin image image-multi smoke k3s-import sbom scan version

help:
	@sed -n '2,13p' Makefile | sed 's/^# \{0,1\}//'
	@echo
	@echo "VERSION=$(VERSION) IMAGE=$(IMAGE) TAG=$(TAG) ARCH=$(ARCH)"

version:
	@echo $(VERSION)

# pip-compile runs inside the Dockerfile's `lock` stage (same base image as the
# builder); the files come back as a tar stream, owned by the caller.
deps-lock:
	docker buildx build --target lockfiles --output type=tar,dest=- . | tar -xf - -C .
	@echo "Updated requirements.lock and requirements-build.lock"

test:
	$(PYTHON) -m pytest -q

# Rendered outputs hold real cluster/S3 config; they are gitignored.
render:
	$(PYTHON) -m logscope render

bin:
	@mkdir -p $(DIST)
	docker buildx build --platform linux/$(ARCH) --target bin $(BUILD_ARGS) \
	    --output type=tar,dest=- . | tar -xOf - logscope > $(BIN).partial
	chmod 0755 $(BIN).partial && mv $(BIN).partial $(BIN)
	cd $(DIST) && sha256sum $(notdir $(BIN)) > $(notdir $(BIN)).sha256
	@ls -l $(BIN)

image:
	docker buildx build --platform linux/$(ARCH) --load $(BUILD_ARGS) -t $(IMAGE):$(TAG) .
	@docker image ls $(IMAGE):$(TAG)

image-multi:
	@if [ "$(PUSH)" != "1" ]; then \
	    echo "image-multi pushes $(IMAGE):$(TAG) for $(PLATFORMS); re-run with PUSH=1 to do it." >&2; exit 1; fi
	docker buildx build --platform $(PLATFORMS) $(BUILD_ARGS) \
	    --sbom=true --provenance=mode=max --push -t $(IMAGE):$(TAG) .

smoke:
	IMAGE=$(IMAGE) TAG=$(TAG) VERSION=$(VERSION) BIN=$(BIN) scripts/smoke.sh

k3s-import:
	@echo "# Single-node k3s without a registry (run on the k3s node, after 'make image'):"
	@echo "docker save $(IMAGE):$(TAG) | sudo k3s ctr images import -"
	@echo "# Then deploy with: --set image.repository=$(IMAGE) --set image.tag=$(TAG) --set image.pullPolicy=Never"

# SBOM + provenance attestations need a BuildKit builder that supports them
# (docker-container driver: docker buildx create --use). Falls back to a
# trivy SBOM of the local image.
sbom:
	@mkdir -p $(DIST)
	@if docker buildx build --platform linux/$(ARCH) $(BUILD_ARGS) --sbom=true --provenance=mode=max \
	        --output type=oci,dest=$(DIST)/logscope-$(TAG)-oci.tar . ; then \
	    echo "SBOM and provenance attached in $(DIST)/logscope-$(TAG)-oci.tar"; \
	elif command -v trivy >/dev/null; then \
	    echo "buildx attestations unsupported by this builder; writing a trivy CycloneDX SBOM instead"; \
	    trivy image --quiet --format cyclonedx --output $(DIST)/logscope-$(TAG).cdx.json $(IMAGE):$(TAG) \
	    && echo "Wrote $(DIST)/logscope-$(TAG).cdx.json"; \
	else \
	    echo "No attestation-capable builder and no trivy; see 'docker buildx create --use'" >&2; exit 1; \
	fi

scan:
	@if command -v trivy >/dev/null; then \
	    trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 $(IMAGE):$(TAG); \
	else echo "trivy not installed; skipping scan"; fi
