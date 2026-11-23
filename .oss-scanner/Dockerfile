# Build environment for Anthropic's OSS Scanner (https://red.anthropic.com/oss-scanner/).
# The scanner builds this with the repository as the build context and runs the result with no network,
# so every dependency is fetched here.
ARG NIM_VERSION=2.2.14
FROM nimlang/nim:${NIM_VERSION}
ARG NIM_VERSION
# Same nimble as CI (v0.24.1).
ARG NIMBLE_COMMIT=aa8e6ea09ecac774b6fad42552569ce07bef37ec
ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/root/.nimble/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential git make python3 \
    && rm -rf /var/lib/apt/lists/*

RUN nimble install "nimble@#${NIMBLE_COMMIT}" -y

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fetch libp2p and test dependencies into nimbledeps/ and tests/nimbledeps/.
RUN make NIM_VERSION="${NIM_VERSION}" setup

# Build the unit-test runner the way CI does, with debug info and frame pointers.
RUN nim c --nimcache:nimcache/test_all --mm:refc --opt:speed --threads:on --skipUserCfg \
      --styleCheck:usages --styleCheck:error --parallelBuild:0 \
      -d:chronicles_log_level=INFO \
      --debugger:native --stacktrace:off --define:nimStackTraceOverride \
      --passC:-fno-omit-frame-pointer \
      tests/test_all.nim
# The full suite takes ~45 min, longer than the scanner's build budget, so it is not run here.
