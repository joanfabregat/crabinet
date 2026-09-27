# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM scratch

ARG TARGETARCH
ARG VERSION
LABEL org.opencontainers.image.title="Crabinet" \
      org.opencontainers.image.description="Secure multi-user file browser" \
      org.opencontainers.image.source="https://github.com/joanfabregat/crabinet" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

COPY --chmod=0555 release/crabinet-linux-${TARGETARCH}/crabinet /crabinet
COPY --chmod=0444 LICENSE-CCADB /licenses/LICENSE-CCADB
COPY --chmod=0444 LICENSE-Apache-2.0 /licenses/LICENSE-Apache-2.0
COPY --chmod=0444 LICENSE-MPL-2.0 /licenses/LICENSE-MPL-2.0

USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/crabinet"]
ENTRYPOINT ["/crabinet"]
