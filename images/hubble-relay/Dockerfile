# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# distroless images are signed by cosign. You should verify the image with the following public key:
# $ cat cosign.pub
# -----BEGIN PUBLIC KEY-----
# MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWZzVzkb8A+DbgDpaJId/bOmV8n7Q
# OqxYbK0Iro6GzSmOzxkn+N2AKawLyXi84WSwJQBK//psATakCgAQKkNTAA==
# -----END PUBLIC KEY-----
# $ cosign verify --key cosign.pub $BASE_IMAGE
# The key may be found at the following address:
# https://raw.githubusercontent.com/GoogleContainerTools/distroless/main/cosign.pub
ARG BASE_IMAGE=gcr.io/distroless/static-debian11:nonroot@sha256:f41b84cda410b05cc690c2e33d1973a31c6165a2721e2b5343aab50fecb63441
ARG GOLANG_IMAGE=docker.io/library/golang:1.22.4@sha256:c2010b9c2342431a24a2e64e33d9eb2e484af49e72c820e200d332d214d5e61f
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:283b3ff907f1eb0a3e12104ebae6fcc84d8be430@sha256:e55c9787c1b02bb6b9bb3149d8f64f182bf6ae400f18a0ec8fb6e4b82648ac79

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
# MODIFIERS are extra arguments to be passed to make at build time.
ARG MODIFIERS

WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    make GOARCH=${TARGETARCH} DESTDIR=/out/${TARGETOS}/${TARGETARCH} ${MODIFIERS} \
    build-container-hubble-relay install-container-binary-hubble-relay

WORKDIR /go/src/github.com/cilium/cilium
# licenses-all is a "script" that executes "go run" so its ARCH should be set
# to the same ARCH specified in the base image of this Docker stage (BUILDARCH)
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    make GOARCH=${BUILDARCH} licenses-all && mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as gops

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    ./build-gops.sh

#
# gRPC health probes
#
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} as grpc_health_probe
ARG BUILDPLATFORM
COPY images/hubble-relay/download-grpc-health-probe.sh /tmp/download-grpc-health-probe.sh
RUN /tmp/download-grpc-health-probe.sh

FROM ${BASE_IMAGE} as release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /bin/gops
COPY --from=grpc_health_probe /out/${TARGETOS}/${TARGETARCH}/bin/grpc_health_probe /bin/grpc_health_probe
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/hubble-relay /usr/bin/hubble-relay
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all
# use uid:gid for the nonroot user for compatibility with runAsNonRoot
USER 65532:65532
ENTRYPOINT ["/usr/bin/hubble-relay"]
CMD ["serve"]
