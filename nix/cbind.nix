{ pkgs, src }:

let
  deps = import ./deps.nix { inherit pkgs; };
  cbindDeps = import ./cbind-deps.nix { inherit pkgs; };

  pathArgs =
    builtins.concatStringsSep " "
      (map (p: "--path:${p}") (builtins.attrValues deps));

  cbindPathArgs =
    builtins.concatStringsSep " "
      (map (p: "--path:${p}") (builtins.attrValues cbindDeps));

  libExt =
    if pkgs.stdenv.hostPlatform.isWindows then "dll"
    else if pkgs.stdenv.hostPlatform.isDarwin then "dylib"
    else "so";

  tinycborVendor = "${cbindDeps.ffi}/ffi/codegen/templates/cpp/vendor/tinycbor";
in
pkgs.stdenv.mkDerivation {
  pname = "nim-libp2p-cbind";
  version = "dev";

  inherit src;

  nativeBuildInputs = [
    pkgs.nim-2_2
    pkgs.git
    pkgs.nimble
  ];

  buildPhase = ''
    export HOME=$TMPDIR
    export XDG_CACHE_HOME=$TMPDIR/.cache
    export NIMBLE_DIR=$TMPDIR/.nimble
    export NIMCACHE=$TMPDIR/nimcache

    mkdir -p build $NIMCACHE

    # libplum's vendored C sources compile into libp2p via nim's {.compile.}
    # pragmas, so there is no separate NAT library to build or link.

    # ffiThreadExitTimeoutMs: bound the FFI thread's graceful-shutdown wait; the
    # 1500ms default is too tight for libp2pDestroy's switch.stop() over many conns.
    # RfcUtcTime: libc localtime() writes one static buffer for all FFI threads.
    commonArgs="--noNimblePath ${cbindPathArgs} ${pathArgs} \
      --threads:on --opt:size --noMain --mm:refc --d:metrics \
      -d:ffiThreadExitTimeoutMs=5000 -d:chronicles_timestamps=RfcUtcTime \
      --nimMainPrefix:liblibp2p --nimcache:$NIMCACHE"

    echo "== Building FFI library (dynamic/shared) =="
    nim c $commonArgs --app:lib --out:build/liblibp2p.${libExt} cbind/libp2p.nim

    echo "== Building FFI library (static) =="
    nim c $commonArgs --app:staticlib --out:build/liblibp2p.a cbind/libp2p.nim

    echo "== Generating C bindings =="
    nim c $commonArgs --app:lib -d:ffiGenBindings -d:targetLang=c \
      -d:ffiOutputDir=cbind/c_bindings -d:ffiSrcPath=libp2p.nim \
      -o:/dev/null cbind/libp2p.nim

    echo "== Generating CDDL schema =="
    nim c $commonArgs --app:lib -d:ffiGenBindings -d:targetLang=cddl \
      -d:ffiOutputDir=cbind/cddl_bindings -d:ffiSrcPath=libp2p.nim \
      -o:/dev/null cbind/libp2p.nim
  '';

  installPhase = ''
    mkdir -p $out/lib $out/include
    cp build/liblibp2p.${libExt} $out/lib
    cp build/liblibp2p.a         $out/lib
    # Install nim-ffi's headers (libp2p.h + companions) flat: consumers stage
    # them via `cp $out/include/*.h`, so a nested dir would be missed.
    cp cbind/c_bindings/*.h   $out/include/
    # libp2p.h includes <tinycbor/cbor.h>; ship the vendored runtime so the
    # installed header set compiles without an external TinyCBOR.
    mkdir -p $out/include/tinycbor
    cp ${tinycborVendor}/* $out/include/tinycbor/
    cp -r cbind/cddl_bindings $out/include/
  '';
}
