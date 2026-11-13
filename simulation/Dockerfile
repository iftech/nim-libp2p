# Build context must be the repo root:
#   docker build -f simulation/Dockerfile -t nim-libp2p/simulation .
FROM nimlang/nim:2.2.14 AS build

WORKDIR /node
COPY . .

# Set up root libp2p deps, then the simulation-specific deps.
RUN nimble -l setup -y && \
    cd simulation && nimble -l setup -y

RUN cd simulation && nim c \
    -d:chronicles_sinks=json \
    --threads:on \
    -d:metrics -d:libp2p_network_protocols_metrics -d:release \
    main.nim

FROM ubuntu:noble

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    iproute2 \
    ethtool \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /node

COPY --from=build /node/simulation/main /node/main

COPY simulation/entrypoint.sh .

RUN chmod +x main entrypoint.sh

EXPOSE 5000 8008

ENTRYPOINT ["./entrypoint.sh"]
