.PHONY: all build deps cbind clean test \
        test_multiformat_exts test_integration test_autotls_docker_integration \
        bench_dial \
        setup lock gen_multicodec format clean-nim

NIM_VERSION  ?= 2.2.10
NPH_VERSION  ?= 0.7.0

NIMC     ?= nim
NIMFLAGS ?=
V        ?= 0

ifeq ($(V),0)
VERBOSITY_FLAG = --verbosity:0
else
VERBOSITY_FLAG =
endif

# Off by default: mingw gcc ships no ASan runtime.
ASAN ?= 0
ifeq ($(ASAN),1)
ASAN_FLAGS = \
  --mm:orc \
  -d:useMalloc \
  --debugger:native \
  --passC:-fno-omit-frame-pointer \
  --passC:-fsanitize=address \
  --passL:-fsanitize=address
export ASAN_OPTIONS = detect_leaks=0
endif

NIM_FLAGS = \
  --styleCheck:usages --styleCheck:error \
  $(VERBOSITY_FLAG) \
  --skipUserCfg \
  -f \
  --threads:on \
  --opt:speed \
  $(ASAN_FLAGS) \
  $(NIMFLAGS)

RUNNER_FLAGS = --output-level=VERBOSE --console

# Allow: make test [path]
# Captures the optional path argument and synthesises a do-nothing rule for it
# so Make does not complain about a missing target.
ifeq ($(firstword $(MAKECMDGOALS)),test)
  _TEST_PATH_ARG := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  ifneq ($(_TEST_PATH_ARG),)
    override TEST_PATH := $(_TEST_PATH_ARG)
    $(eval $(_TEST_PATH_ARG):;@true)
  endif
endif

TEST_PATH ?=

all: setup

nix/libp2p.lock: libp2p.nimble
	nimble --lockFile:$@ --requires:"nim == $(NIM_VERSION)" lock

nix/deps.nix: nix/libp2p.lock
	./tools/gen-deps.sh nix/libp2p.lock nix/deps.nix

deps: nix/deps.nix

build: deps
	nix build

cbind:
	$(MAKE) -C cbind

clean:
	$(RM) nix/deps.nix nimble.paths tests/nimble.paths
	$(MAKE) -C cbind clean

nimble.paths: libp2p.nimble
	nimble --noLockfile --requires:"nim == $(NIM_VERSION)" --resolver:minver -l setup -y

tests/nimble.paths: tests/tests.nimble libp2p.nimble
	cd tests && nimble --requires:"nim == $(NIM_VERSION)" --resolver:minver -l setup -y

# nim-libplum vendors libplum (PCP / NAT-PMP / UPnP-IGD) as a git submodule and
# compiles its C sources into libp2p via nim's {.compile.} pragmas, so there is
# no separate NAT library to build or link here.

test: nimble.paths tests/nimble.paths
ifeq ($(TEST_PATH),)
	$(NIMC) c $(NIM_FLAGS) \
	  --nimcache:nimcache/test_all \
	  tests/test_all.nim
	./tests/test_all $(RUNNER_FLAGS) --xml:tests/results_test_all.xml
	$(MAKE) test_multiformat_exts
else
	$(NIMC) c $(NIM_FLAGS) \
	  --nimcache:nimcache/test_all \
	  -d:path=$(TEST_PATH) \
	  tests/test_all.nim
	./tests/test_all $(RUNNER_FLAGS) --xml:tests/results_test_all.xml
endif

test_multiformat_exts: nimble.paths tests/nimble.paths
	$(NIMC) c $(NIM_FLAGS) \
	  --nimcache:nimcache/test_all_multiformat \
	  -d:libp2p_multicodec_exts=../tests/libp2p/multiformat_exts/multicodec_exts.nim \
	  -d:libp2p_multiaddress_exts=../tests/libp2p/multiformat_exts/multiaddress_exts.nim \
	  -d:libp2p_multihash_exts=../tests/libp2p/multiformat_exts/multihash_exts.nim \
	  -d:libp2p_multibase_exts=../tests/libp2p/multiformat_exts/multibase_exts.nim \
	  -d:libp2p_contentids_exts=../tests/libp2p/multiformat_exts/contentids_exts.nim \
	  -d:path=multiformat_exts \
	  tests/test_all.nim
	./tests/test_all $(RUNNER_FLAGS) --xml:tests/results_test_all_multiformat.xml

test_integration: nimble.paths tests/nimble.paths
	$(NIMC) c $(NIM_FLAGS) \
	  $(if $(CICOV),--nimcache:nimcache/integration,) \
	  tests/integration/test_all.nim
	./tests/integration/test_all $(RUNNER_FLAGS) --xml:tests/results_integration.xml

BENCH_LOG_LEVEL ?= WARN

bench_dial: nimble.paths tests/nimble.paths
	mkdir -p $(CURDIR)/build
	$(NIMC) c $(NIM_FLAGS) \
	  --nimcache:nimcache/bench_dial \
	  -d:chronicles_log_level=$(BENCH_LOG_LEVEL) \
	  -o:$(CURDIR)/build/bench_dial \
	  tests/benchmarks/bench_dial.nim
	./build/bench_dial

test_autotls_docker_integration:
	docker compose -f tests/integration/autotls_docker/docker-compose.yml build test
	status=0; docker compose -f tests/integration/autotls_docker/docker-compose.yml run --rm test || status=$$?; \
	  [ $$status -eq 0 ] || docker compose -f tests/integration/autotls_docker/docker-compose.yml logs; \
	  docker compose -f tests/integration/autotls_docker/docker-compose.yml down -v; \
	  exit $$status

setup:
	$(MAKE) nimble.paths tests/nimble.paths

lock: nix/libp2p.lock
	$(MAKE) -C cbind nimble.lock

gen_multicodec:
	nimble gen_multicodec

format:
	find . \( -name '*.nim' -o -name '*.nimble' \) -not -path './nimbledeps/*' -not -path './tests/nimbledeps/*' | xargs nph

clean-nim:
	[ ! -d nimbledeps ] || rm -rf nimbledeps
	[ ! -d tests/nimbledeps ] || rm -rf tests/nimbledeps
	rm nimble.paths tests/nimble.paths 2>/dev/null || true
