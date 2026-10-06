{ pkgs
, src
, targetName
, sdk
, platformName
, targetTriple
, nimCpu ? "arm64"
, minVersion ? "13.0"
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

  minVersionFlag =
    if sdk == "iphonesimulator"
    then "-mios-simulator-version-min=${minVersion}"
    else "-miphoneos-version-min=${minVersion}";

  platformCheck =
    if sdk == "iphonesimulator"
    then "platform (IOSSIMULATOR|7)|LC_VERSION_MIN_IPHONEOS"
    else "platform (IOS|2)|LC_VERSION_MIN_IPHONEOS";

  tinycborVendor = "${cbindDeps.ffi}/ffi/codegen/templates/cpp/vendor/tinycbor";
in
pkgs.stdenv.mkDerivation {
  pname = "nim-libp2p-cbind-ffi-ios-${targetName}";
  version = "dev";

  inherit src;

  nativeBuildInputs = [
    pkgs.nim-2_2
    pkgs.git
    pkgs.nimble
    pkgs.gnumake
    pkgs.which
    pkgs.file
  ];

  # iOS SDKs come from Xcode on the host macOS runner, not from nixpkgs.
  # The GitHub workflow disables the Nix sandbox so the derivation can
  # access the host Xcode SDKs.
  __noChroot = true;

  # iOS Mach-O files are target artifacts; host fixup/patchelf would be wrong.
  dontFixup = true;

  buildPhase = ''
    export HOME=$TMPDIR
    export XDG_CACHE_HOME=$TMPDIR/.cache
    export NIMBLE_DIR=$TMPDIR/.nimble
    export NIMCACHE=$TMPDIR/nimcache

    export IOS_SDK_NAME=${sdk}
    case "$IOS_SDK_NAME" in
      iphoneos)
        IOS_PLATFORM_DIR=iPhoneOS.platform
        IOS_SDK_PREFIX=iPhoneOS
        ;;
      iphonesimulator)
        IOS_PLATFORM_DIR=iPhoneSimulator.platform
        IOS_SDK_PREFIX=iPhoneSimulator
        ;;
      *)
        echo "unsupported iOS SDK: $IOS_SDK_NAME" >&2
        exit 1
        ;;
    esac

    IOS_DEVELOPER_DIR=
    for candidate in /Applications/Xcode*.app/Contents/Developer; do
      if [ -d "$candidate/Platforms/$IOS_PLATFORM_DIR/Developer/SDKs" ]; then
        IOS_DEVELOPER_DIR="$candidate"
      fi
    done
    if [ -z "$IOS_DEVELOPER_DIR" ]; then
      echo "Xcode with $IOS_PLATFORM_DIR SDKs is required for iOS builds" >&2
      exit 1
    fi
    export IOS_DEVELOPER_DIR
    export DEVELOPER_DIR="$IOS_DEVELOPER_DIR"

    IOS_SDK_PATH=
    for candidate in "$IOS_DEVELOPER_DIR/Platforms/$IOS_PLATFORM_DIR/Developer/SDKs/$IOS_SDK_PREFIX"*.sdk; do
      if [ -d "$candidate" ]; then
        IOS_SDK_PATH="$candidate"
      fi
    done
    if [ -z "$IOS_SDK_PATH" ]; then
      echo "unable to find $IOS_SDK_NAME SDK under $IOS_DEVELOPER_DIR" >&2
      exit 1
    fi
    export IOS_SDK_PATH
    export SDKROOT="$IOS_SDK_PATH"

    IOS_TOOLCHAIN="$IOS_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin"
    export IOS_CLANG="$IOS_TOOLCHAIN/clang"
    export IOS_CLANGXX="$IOS_TOOLCHAIN/clang++"
    export IOS_AR="$IOS_TOOLCHAIN/ar"
    export IOS_RANLIB="$IOS_TOOLCHAIN/ranlib"
    export IOS_OTOOL="$IOS_TOOLCHAIN/otool"
    export IOS_LIPO="$IOS_TOOLCHAIN/lipo"
    for tool in "$IOS_CLANG" "$IOS_CLANGXX" "$IOS_AR" "$IOS_RANLIB" "$IOS_OTOOL" "$IOS_LIPO"; do
      if [ ! -x "$tool" ]; then
        echo "missing Xcode tool: $tool" >&2
        exit 1
      fi
    done
    export IOS_TARGET_TRIPLE=${targetTriple}
    export IOS_MIN_VERSION_FLAG=${minVersionFlag}

    TOOLCHAIN=$TMPDIR/ios-toolchain
    mkdir -p build $NIMCACHE "$TOOLCHAIN"

    cat > "$TOOLCHAIN/clang" <<'EOF'
#!${pkgs.bash}/bin/bash
export DEVELOPER_DIR="$IOS_DEVELOPER_DIR"
export SDKROOT="$IOS_SDK_PATH"
exec "$IOS_CLANG" \
  -target "$IOS_TARGET_TRIPLE" \
  -isysroot "$IOS_SDK_PATH" \
  "$IOS_MIN_VERSION_FLAG" \
  "$@"
EOF
    cat > "$TOOLCHAIN/clang++" <<'EOF'
#!${pkgs.bash}/bin/bash
export DEVELOPER_DIR="$IOS_DEVELOPER_DIR"
export SDKROOT="$IOS_SDK_PATH"
exec "$IOS_CLANGXX" \
  -target "$IOS_TARGET_TRIPLE" \
  -isysroot "$IOS_SDK_PATH" \
  "$IOS_MIN_VERSION_FLAG" \
  "$@"
EOF
    cat > "$TOOLCHAIN/ar" <<'EOF'
#!${pkgs.bash}/bin/bash
export DEVELOPER_DIR="$IOS_DEVELOPER_DIR"
export SDKROOT="$IOS_SDK_PATH"
exec "$IOS_AR" "$@"
EOF
    cat > "$TOOLCHAIN/ranlib" <<'EOF'
#!${pkgs.bash}/bin/bash
export DEVELOPER_DIR="$IOS_DEVELOPER_DIR"
export SDKROOT="$IOS_SDK_PATH"
exec "$IOS_RANLIB" "$@"
EOF
    ln -s "$TOOLCHAIN/ar" "$TOOLCHAIN/llvm-ar"
    ln -s "$TOOLCHAIN/ranlib" "$TOOLCHAIN/llvm-ranlib"
    chmod +x "$TOOLCHAIN"/clang "$TOOLCHAIN"/clang++ "$TOOLCHAIN"/ar "$TOOLCHAIN"/ranlib

    export PATH=$TOOLCHAIN:$PATH
    export CC=$TOOLCHAIN/clang
    export CXX=$TOOLCHAIN/clang++
    export AR=$TOOLCHAIN/ar
    export RANLIB=$TOOLCHAIN/ranlib

    # ffiThreadExitTimeoutMs: bound the FFI thread's graceful-shutdown wait; the
    # 1500ms default is too tight for libp2pDestroy's switch.stop() over many conns.
    # RfcUtcTime: libc localtime() writes one static buffer for all FFI threads.
    commonArgs="--noNimblePath ${cbindPathArgs} ${pathArgs} \
      --os:ios --cpu:${nimCpu} --cc:clang \
      --clang.path:$TOOLCHAIN \
      --clang.exe:clang --clang.linkerexe:clang++ \
      --passC:-fPIC --passC:-D_DARWIN_C_SOURCE \
      --passL:-lc++ \
      --threads:on --opt:size --noMain --mm:refc --d:metrics \
      -d:ffiThreadExitTimeoutMs=5000 -d:chronicles_timestamps=RfcUtcTime \
      --nimMainPrefix:liblibp2p --nimcache:$NIMCACHE"

    echo "== Building iOS FFI library (dynamic/shared) for ${targetName} =="
    nim c $commonArgs --app:lib --out:build/liblibp2p.dylib cbind/libp2p.nim

    echo "== Building iOS FFI library (static) for ${targetName} =="
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

    echo "== Compiling iOS C check harness for ${targetName} =="
    mkdir -p build/check-objects
    "$CC" -std=c11 -fPIE -pthread \
      -I cbind/c_bindings -I cbind/c_bindings/tinycbor \
      -c cbind/examples/libp2p_mobile_check.c \
      -o build/check-objects/libp2p_ios_check.o
    for src in cbind/c_bindings/tinycbor/*.c; do
      obj=build/check-objects/$(basename "$src" .c).o
      "$CC" -std=c11 -fPIE -I cbind/c_bindings/tinycbor -c "$src" -o "$obj"
    done
    "$CXX" -fPIE -pthread \
      build/check-objects/*.o build/liblibp2p.dylib \
      -lc++ \
      -o build/libp2p_ios_check

    echo "== Inspecting iOS artifacts for ${targetName} =="
    "$IOS_OTOOL" -l build/liblibp2p.dylib | tee build/liblibp2p.dylib.otool
    "$IOS_OTOOL" -l build/liblibp2p.a | tee build/liblibp2p.a.otool
    "$IOS_OTOOL" -l build/libp2p_ios_check | tee build/libp2p_ios_check.otool
    "$IOS_LIPO" -info build/liblibp2p.dylib | tee build/liblibp2p.dylib.lipo
    "$IOS_LIPO" -info build/liblibp2p.a | tee build/liblibp2p.a.lipo
    "$IOS_LIPO" -info build/libp2p_ios_check | tee build/libp2p_ios_check.lipo
    grep -Eq "${platformCheck}" build/liblibp2p.dylib.otool
    grep -Eq "${platformCheck}" build/liblibp2p.a.otool
    grep -Eq "${platformCheck}" build/libp2p_ios_check.otool
    grep -q "arm64" build/liblibp2p.dylib.lipo
    grep -q "arm64" build/liblibp2p.a.lipo
    grep -q "arm64" build/libp2p_ios_check.lipo
  '';

  installPhase = ''
    mkdir -p $out/lib $out/include $out/bin $out/nix-support

    cp build/liblibp2p.dylib $out/lib/
    cp build/liblibp2p.a     $out/lib/

    cp cbind/c_bindings/*.h $out/include/
    cp -r cbind/c_bindings/tinycbor $out/include/
    cp -r cbind/cddl_bindings $out/include/

    cp build/libp2p_ios_check $out/bin/
    cp build/*.otool build/*.lipo $out/nix-support/

    printf '%s\n' \
      "target=${targetName}" \
      "sdk=${sdk}" \
      "platform=${platformName}" \
      "min_version=${minVersion}" \
      "target_triple=${targetTriple}" \
      "nim_cpu=${nimCpu}" \
      > $out/nix-support/ios-target
  '';

  meta = with pkgs.lib; {
    description = "iOS ${targetName} C ABI build of nim-libp2p libp2p";
    platforms = platforms.darwin;
  };
}
