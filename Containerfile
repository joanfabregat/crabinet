# syntax=docker/dockerfile:1.7
FROM scratch

ARG TARGETARCH
ARG VERSION
LABEL org.opencontainers.image.title="Index" \
      org.opencontainers.image.description="Secure multi-user file browser" \
      org.opencontainers.image.source="https://github.com/joanfabregat/index" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

COPY --chmod=0555 release/index-linux-${TARGETARCH}/index /index

USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/index"]
ENTRYPOINT ["/index"]
