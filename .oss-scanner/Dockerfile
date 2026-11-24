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
      ca-certificates build-essential curl git make python3 \
    && rm -rf /var/lib/apt/lists/*

RUN nimble install "nimble@#${NIMBLE_COMMIT}" -y

# Same nph as the linters workflow, so `make format` works offline.
ARG NPH_VERSION=0.7.0
ARG NPH_SHA256=1a01337e704e18471cf5d584547ff82ce92cb54df1e44b25c5027c73cc67479f
RUN curl -fsSL -o /tmp/nph.tgz \
      "https://github.com/arnetheduck/nph/releases/download/v${NPH_VERSION}/nph-linux_x64.tar.gz" \
    && echo "${NPH_SHA256}  /tmp/nph.tgz" | sha256sum -c - \
    && tar xzf /tmp/nph.tgz -C /usr/local/bin nph \
    && rm /tmp/nph.tgz

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
