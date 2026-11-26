.PHONY: all build genbindings test deps nixbuild clean

NIM_VERSION ?= 2.2.14

all: build genbindings

# Builds ../build/liblibp2p.so plus the C/CDDL bindings. Run `nimble -l setup -y` once first.
build:
	nimble buildffi

genbindings:
	nimble genbindings_c
	nimble genbindings_cddl

test:
	nimble test

nimble.lock: cbind.nimble
	nimble --requires:"nim == $(NIM_VERSION)" lock

../nix/cbind-deps.nix: nimble.lock
	../tools/gen-deps.sh nimble.lock ../nix/cbind-deps.nix taskpools cbor_serialization ffi

deps: ../nix/cbind-deps.nix

nixbuild: deps
	nix build .#cbind

clean:
	$(RM) -r c_bindings cddl_bindings nimcache nimcache_asan nimcache_tsan nimcache_c nimcache_cddl nimcache_test nimcache_test_asan nimcache_test_tsan
