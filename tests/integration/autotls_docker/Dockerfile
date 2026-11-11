# syntax=docker/dockerfile:1.5-labs
# Runs test_autotls_docker.nim inside the containers' network namespace.
ARG NIM_VERSION=2.2.14
ARG NIMBLE_COMMIT=aa8e6ea09ecac774b6fad42552569ce07bef37ec
FROM nimlang/nim:${NIM_VERSION}
ARG NIM_VERSION
ARG NIMBLE_COMMIT
ENV PATH="/root/.nimble/bin:/opt/nim/bin:${PATH}"

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt apt-get update && apt-get install -y --no-install-recommends ca-certificates make \
    && rm -rf /var/lib/apt/lists/*

RUN nimble install "nimble@#${NIMBLE_COMMIT}" -y

COPY . .

RUN make NIM_VERSION=${NIM_VERSION} clean-nim setup

RUN nim c -o:/app/test_autotls_docker tests/integration/autotls_docker/test_autotls_docker.nim

CMD ["/app/test_autotls_docker", "--output-level=VERBOSE", "--console"]
