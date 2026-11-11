# syntax=docker/dockerfile:1.5-labs
ARG NIM_VERSION=2.2.12
ARG NIMBLE_COMMIT=aa8e6ea09ecac774b6fad42552569ce07bef37ec
FROM nimlang/nim:${NIM_VERSION} as builder
ARG NIM_VERSION
ARG NIMBLE_COMMIT
ENV PATH="/root/.nimble/bin:/opt/nim/bin:${PATH}"

WORKDIR /app

COPY libp2p.nimble nim-libp2p/
COPY interop/hole-punching/interop_hole_punching.nimble nim-libp2p/interop/hole-punching/

RUN --mount=type=cache,target=/var/cache/apt apt-get update && apt-get install -y --no-install-recommends ca-certificates binutils libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN nimble install "nimble@#${NIMBLE_COMMIT}" -y

COPY . nim-libp2p/

RUN cd nim-libp2p/interop/hole-punching && \
  nimble --noLockfile --requires:"nim == ${NIM_VERSION}" --resolver:minver -l setup -y && \
  nim c -d:release \
  --mm:refc --threads:on \
  -d:chronicles_log_level=INFO -d:chronicles_default_output_device=stderr -d:chronicles_colors=None \
  -o:/app/peer hole_punching.nim

FROM debian:trixie-slim
# The upstream harness runs these tools in participant containers before the client.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bind9-dnsutils curl iproute2 jq tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/peer /usr/bin/nim-hole-punch-client
COPY interop/hole-punching/hole-punch-client.sh /usr/bin/hole-punch-client
COPY interop/hole-punching/hole-punch-router-nat.sh /usr/bin/hole-punch-router-nat
COPY interop/hole-punching/hole-punch-entrypoint.sh /usr/bin/hole-punch-entrypoint
RUN chmod +x /usr/bin/hole-punch-client /usr/bin/hole-punch-router-nat /usr/bin/hole-punch-entrypoint
ENTRYPOINT ["/usr/bin/hole-punch-entrypoint"]
CMD ["hole-punch-client"]
