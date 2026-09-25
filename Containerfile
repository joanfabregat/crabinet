# syntax=docker/dockerfile:1.7
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

USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/crabinet"]
ENTRYPOINT ["/crabinet"]
