# syntax=docker/dockerfile:1.5-labs
ARG NIM_VERSION=2.2.14
ARG NIMBLE_COMMIT=aa8e6ea09ecac774b6fad42552569ce07bef37ec
FROM nimlang/nim:${NIM_VERSION} as builder
ARG NIM_VERSION
ARG NIMBLE_COMMIT
ENV PATH="/root/.nimble/bin:/opt/nim/bin:${PATH}"

WORKDIR /app

COPY libp2p.nimble nim-libp2p/
COPY interop/perf/interop_perf.nimble nim-libp2p/interop/perf/

RUN --mount=type=cache,target=/var/cache/apt apt-get update && apt-get install -y --no-install-recommends ca-certificates binutils \
    && rm -rf /var/lib/apt/lists/*

RUN nimble install "nimble@#${NIMBLE_COMMIT}" -y

COPY . nim-libp2p/

RUN \
  cd nim-libp2p/interop/perf && \
  nimble --noLockfile --requires:"nim == ${NIM_VERSION}" --resolver:minver -l setup -y && \
  nim c -d:release \
  --mm:refc --threads:on \
  -d:chronicles_log_level=INFO -d:chronicles_default_output_device=stderr -d:chronicles_colors=None \
  -o:/app/perf-interop main.nim

FROM debian:trixie-slim AS runtime

COPY --from=builder /app/perf-interop /app/perf-interop

ENTRYPOINT ["/app/perf-interop"]
