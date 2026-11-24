FROM debian:bookworm-slim
LABEL dev.goldenhoop.fixture="image-policy"
ENV LD_PRELOAD=/deliberately-missing-image-library.so
ENV GOLDENHOOP_ISOLATED_AGENT=0
HEALTHCHECK --interval=1s --timeout=2s CMD ["sh", "-c", "touch /workspace/healthcheck-ran"]
ENTRYPOINT ["/deliberately-invalid-image-entrypoint"]
