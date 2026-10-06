{ pkgs
, src
, abi
, androidTriple
, nimCpu
, androidApi ? 23
}:

let
  deps = import ./deps.nix { inherit pkgs; };
  cbindDeps = import ./cbind-deps.nix { inherit pkgs; };

  pathArgs =
    builtins.concatStringsSep " "
      (map (p: "--path:${p}") (builtins.attrValues deps));

  cbindPathArgs =
    builtins.concatStringsSep " "
      (map (p: "--path:${p}") (builtins.attrValues cbindDeps));

  androidApiString = toString androidApi;
  androidCcName = "${androidTriple}${androidApiString}-clang";
  androidCxxName = "${androidTriple}${androidApiString}-clang++";

  androidHostTag =
    if pkgs.stdenv.hostPlatform.system == "aarch64-darwin" then "darwin-arm64"
    else if pkgs.stdenv.hostPlatform.isDarwin then "darwin-x86_64"
    else if pkgs.stdenv.hostPlatform.system == "aarch64-linux" then "linux-aarch64"
    else "linux-x86_64";

  androidComposition = pkgs.androidenv.composeAndroidPackages {
    cmdLineToolsVersion = "9.0";
    toolsVersion = "26.1.1";
    platformToolsVersion = "34.0.5";
    buildToolsVersions = [ "34.0.0" ];
    platformVersions = [ androidApiString ];
    includeCmake = false;
    ndkVersion = "27.2.12479018";
    includeNDK = true;
  };

  androidSdk = androidComposition.androidsdk;
  tinycborVendor = "${cbindDeps.ffi}/ffi/codegen/templates/cpp/vendor/tinycbor";
in
pkgs.stdenv.mkDerivation {
  pname = "nim-libp2p-cbind-ffi-android-${abi}";
  version = "dev";

  inherit src;

  nativeBuildInputs = [
    pkgs.nim-2_2
    pkgs.git
    pkgs.nimble
    pkgs.gnumake
    pkgs.which
    pkgs.file
    pkgs.binutils
  ];

  # Android ELF files are not host ELF files; host fixup/patchelf would be wrong.
  dontFixup = true;

  buildPhase = ''
    export HOME=$TMPDIR
    export XDG_CACHE_HOME=$TMPDIR/.cache
    export NIMBLE_DIR=$TMPDIR/.nimble
    export NIMCACHE=$TMPDIR/nimcache

    export ANDROID_SDK_ROOT=${androidSdk}/libexec/android-sdk
    export ANDROID_NDK_ROOT=$ANDROID_SDK_ROOT/ndk-bundle

    ANDROID_TOOLCHAIN=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/${androidHostTag}
    export PATH=$ANDROID_TOOLCHAIN/bin:$PATH

    export ANDROID_CC=$ANDROID_TOOLCHAIN/bin/${androidCcName}
    export ANDROID_CXX=$ANDROID_TOOLCHAIN/bin/${androidCxxName}
    export ANDROID_AR=$ANDROID_TOOLCHAIN/bin/llvm-ar
    export ANDROID_RANLIB=$ANDROID_TOOLCHAIN/bin/llvm-ranlib
    export ANDROID_READELF=$ANDROID_TOOLCHAIN/bin/llvm-readelf
    export ANDROID_CXX_STDLIB=$ANDROID_TOOLCHAIN/sysroot/usr/lib/${androidTriple}/libc++_shared.so

    if [ ! -x "$ANDROID_CC" ]; then
      echo "missing Android clang: $ANDROID_CC" >&2
      exit 1
    fi
    if [ ! -x "$ANDROID_CXX" ]; then
      echo "missing Android clang++: $ANDROID_CXX" >&2
      exit 1
    fi
    if [ ! -f "$ANDROID_CXX_STDLIB" ]; then
      echo "missing Android libc++_shared.so: $ANDROID_CXX_STDLIB" >&2
      exit 1
    fi

    mkdir -p build $NIMCACHE
    echo 'INPUT(-lc)' > build/libpthread.so

    # ffiThreadExitTimeoutMs: bound the FFI thread's graceful-shutdown wait; the
    # 1500ms default is too tight for libp2pDestroy's switch.stop() over many conns.
    # RfcUtcTime: libc localtime() writes one static buffer for all FFI threads.
    commonArgs="--noNimblePath ${cbindPathArgs} ${pathArgs} \
      --os:android --cpu:${nimCpu} --cc:clang \
      --clang.path:$ANDROID_TOOLCHAIN/bin \
      --clang.exe:${androidCcName} --clang.linkerexe:${androidCxxName} \
      --passC:-DANDROID --passC:-fPIC \
      --passL:-L$PWD/build --passL:-lc++_shared --passL:-llog --passL:-ldl --passL:-lm \
      --threads:on --opt:size --noMain --mm:refc --d:metrics \
      -d:ffiThreadExitTimeoutMs=5000 -d:chronicles_timestamps=RfcUtcTime \
      --nimMainPrefix:liblibp2p --nimcache:$NIMCACHE"

    echo "== Building Android FFI library (shared) for ${abi} =="
    nim c $commonArgs --app:lib --out:build/liblibp2p.so cbind/libp2p.nim

    echo "== Building Android FFI library (static) for ${abi} =="
    nim c $commonArgs --app:staticlib --out:build/liblibp2p.a cbind/libp2p.nim

    echo "== Generating C bindings =="
    nim c $commonArgs --app:lib -d:ffiGenBindings -d:targetLang=c \
      -d:ffiOutputDir=cbind/c_bindings -d:ffiSrcPath=libp2p.nim \
      -o:/dev/null cbind/libp2p.nim

    echo "== Generating CDDL schema =="
    nim c $commonArgs --app:lib -d:ffiGenBindings -d:targetLang=cddl \
      -d:ffiOutputDir=cbind/cddl_bindings -d:ffiSrcPath=libp2p.nim \
      -o:/dev/null cbind/libp2p.nim

    mkdir -p cbind/c_bindings/tinycbor
    cp ${tinycborVendor}/* cbind/c_bindings/tinycbor/

    echo "== Compiling Android C check harness for ${abi} =="
    mkdir -p build/check-objects
    "$ANDROID_CC" -std=c11 -fPIE -pthread \
      -I cbind/c_bindings -I cbind/c_bindings/tinycbor \
      -c cbind/examples/libp2p_mobile_check.c \
      -o build/check-objects/libp2p_android_check.o
    for src in cbind/c_bindings/tinycbor/*.c; do
      obj=build/check-objects/$(basename "$src" .c).o
      "$ANDROID_CC" -std=c11 -fPIE -I cbind/c_bindings/tinycbor -c "$src" -o "$obj"
    done
    "$ANDROID_CXX" -L build -fPIE -pie -pthread \
      build/check-objects/*.o build/liblibp2p.so \
      -lc++_shared -ldl -lm -llog \
      -o build/libp2p_android_check

    "$ANDROID_READELF" -h build/liblibp2p.so > build/liblibp2p.so.readelf
    "$ANDROID_READELF" -h build/libp2p_android_check > build/libp2p_android_check.readelf
    "$ANDROID_AR" t build/liblibp2p.a > /dev/null
  '';

  installPhase = ''
    mkdir -p $out/lib $out/include $out/bin $out/nix-support

    cp build/liblibp2p.so $out/lib/
    cp build/liblibp2p.a  $out/lib/
    cp "$ANDROID_CXX_STDLIB" $out/lib/
    cp cbind/c_bindings/*.h $out/include/
    cp -r cbind/c_bindings/tinycbor $out/include/
    cp -r cbind/cddl_bindings $out/include/

    cp build/libp2p_android_check $out/bin/
    cp build/*.readelf $out/nix-support/

    printf '%s\n' \
      "abi=${abi}" \
      "android_api=${androidApiString}" \
      "android_triple=${androidTriple}" \
      "nim_cpu=${nimCpu}" \
      "cc=${androidCcName}" \
      > $out/nix-support/android-target
  '';

  meta = with pkgs.lib; {
    description = "Android ${abi} C ABI build of nim-libp2p libp2p";
    platforms = platforms.linux ++ platforms.darwin;
  };
}
