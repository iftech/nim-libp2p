mode = ScriptMode.Verbose

packageName = "cbind"
version = "0.1.0"
author = "Status Research & Development GmbH"
description = "C bindings for nim-libp2p, generated via nim-ffi"
license = "MIT"

import os, strutils

requires "taskpools >= 0.1.0", "ffi >= 0.3.0", "cbor_serialization == 0.3.0"

proc sanitizer(): string =
  ## Sanitizer the examples build under: LIBP2P_SAN=asan|tsan|none. Empty means none.
  # mingw gcc ships no sanitizer runtime, so Windows defaults to none.
  let default = when defined(windows): "none" else: "asan"
  let san = getEnv("LIBP2P_SAN", default)
  if san notin ["asan", "tsan", "none"]:
    raise newException(ValueError, "unknown LIBP2P_SAN: " & san)
  if san == "none": "" else: san

proc nimSanFlags(san: string): string =
  # orc, not the shipped refc: refc's conservative stack scan reads past its
  # `registers` buffer and ASan calls that a stack-buffer-overflow.
  let common =
    " --mm:orc -d:useMalloc --debugger:native --passC:-fno-omit-frame-pointer"
  case san
  of "tsan":
    common & " --passC:-fsanitize=thread --passL:-fsanitize=thread"
  else:
    common & " --passC:-fsanitize=address --passL:-fsanitize=address"

proc ccSanFlags(san: string): string =
  # -O1 for tsan: -O2 inlines away the frames its reports need.
  let common = " -g -fno-omit-frame-pointer"
  case san
  of "":
    " -O2"
  of "tsan":
    " -O1" & common & " -fsanitize=thread"
  else:
    " -O2" & common & " -fsanitize=address"

proc sanRunEnv(san: string): string =
  # ASan needs LSan off: orc frees at collection time, so live objects look like leaks.
  case san
  of "":
    ""
  of "tsan":
    "TSAN_OPTIONS=suppressions=" & thisDir() / "tsan.supp" & " "
  else:
    "ASAN_OPTIONS=detect_leaks=0 "

proc findInstalledPkgDir(prefix: string): string =
  ## Path of an installed dep dir matching `prefix` (e.g. "ffi-"). Lockfile
  ## and local setup use project-local `nimbledeps`; a plain global install
  ## uses the global store. Check both.
  var bases = @[
    "nimbledeps/pkgs2", "nimbledeps/pkgs", "../nimbledeps/pkgs2", "../nimbledeps/pkgs"
  ]
  let home = getEnv("HOME")
  if home.len > 0:
    bases.add home & "/.nimble/pkgs2"
  for base in bases:
    if not dirExists(base):
      continue
    for entry in listDirs(base):
      if entry.extractFilename().startsWith(prefix):
        return entry
  raise newException(
    IOError,
    "could not locate installed package '" & prefix &
      "*'; run `nimble -l setup -y` from cbind first",
  )

proc ffiDepPaths(): string =
  if fileExists("nimble.paths"):
    return ""
  # A global install writes no nimble.paths; point the compiler at the installed
  # copies.
  " --path:" & findInstalledPkgDir("ffi-") & " --path:" &
    findInstalledPkgDir("cbor_serialization-")

proc ffiLibExt(): string =
  when defined(windows):
    "dll"
  elif defined(macosx):
    "dylib"
  else:
    "so"

proc buildFfiLib(san = "") =
  let buildDir = "../build"
  if not dirExists(buildDir):
    mkDir(buildDir)

  let sanFlags =
    if san.len > 0:
      nimSanFlags(san)
    else:
      " --mm:refc"
  let nimcache =
    if san.len > 0:
      "nimcache_" & san
    else:
      "nimcache"
  # libplum's vendored C is pulled in via Nim `{.compile.}`, so no separate
  # native-library build step is needed here.
  # Name the output `lib<name>` so the file matches the soname nim derives from
  # the module; `--nimMainPrefix:liblibp2p` matches the `liblibp2pNimMain` symbol
  # nim-ffi's `declareLibrary` imports.
  # ffiThreadExitTimeoutMs: bound the FFI thread's graceful-shutdown wait; the
  # 1500ms default is too tight for libp2pDestroy's switch.stop() over many conns.
  # RfcUtcTime: libc localtime() writes one static buffer for all FFI threads.
  exec "nim c --out:" & buildDir & "/liblibp2p." & ffiLibExt() &
    " --threads:on --app:lib --opt:size --noMain -d:metrics" & sanFlags &
    " -d:chronicles_runtime_filtering=on -d:chronicles_timestamps=RfcUtcTime" &
    " -d:ffiThreadExitTimeoutMs=5000" & ffiDepPaths() &
    " --nimMainPrefix:liblibp2p --nimcache:" & nimcache & " libp2p.nim"

task buildffi, "Build the FFI shared library":
  buildFfiLib()

proc genBindingsFor(lang, outDir: string) =
  # `--compileOnly`: the binding files are written during macro expansion, so
  # codegen is enough — there is nothing to link.
  exec "nim c --threads:on --noMain --mm:refc -d:metrics --compileOnly" &
    " -d:chronicles_runtime_filtering=on --nimMainPrefix:liblibp2p" &
    " -d:ffiGenBindings -d:targetLang=" & lang & " -d:ffiOutputDir=" & outDir &
    " -d:ffiSrcPath=libp2p.nim" & ffiDepPaths() & " --nimcache:nimcache_" & lang &
    " libp2p.nim"

task genbindings_c, "Generate C bindings (cbind/c_bindings)":
  genBindingsFor("c", "c_bindings")

task genbindings_cddl, "Generate CDDL schema (cbind/cddl_bindings)":
  genBindingsFor("cddl", "cddl_bindings")

proc findFfiVendorDir(): string =
  ## TinyCBOR sources vendored inside the installed nim-ffi package.
  let vendor = findInstalledPkgDir("ffi-") & "/ffi/codegen/templates/cpp/vendor"
  if not fileExists(vendor & "/tinycbor/cbor.h"):
    raise newException(IOError, "vendored tinycbor missing under " & vendor)
  vendor

task examples, "Build and run the C bindings examples":
  let san = sanitizer()
  let ccFlags = ccSanFlags(san)
  let lib = "../build/liblibp2p." & ffiLibExt()
  buildFfiLib(san)
  if not fileExists("c_bindings/libp2p.h"):
    genBindingsFor("c", "c_bindings")

  let vendor = findFfiVendorDir()
  var cborObjs: seq[string]
  for name in [
    "cborencoder", "cborencoder_close_container_checked", "cborparser",
    "cborparser_dup_string", "cborerrorstrings",
  ]:
    let obj = "../build/" & name & ".o"
    exec "gcc -std=c99 -fPIC" & ccFlags & " -I " & vendor & " -I " & vendor &
      "/tinycbor -c " & vendor & "/tinycbor/" & name & ".c -o " & obj
    cborObjs.add obj
  let cborObjsStr = cborObjs.join(" ")

  for example in [
    "echo", "gossipsub", "kad", "service_disco", "relay", "peerstore", "metrics"
  ]:
    let outBin = "../build/" & example
    exec "gcc -std=c11" & ccFlags & " -I c_bindings -I " & vendor & " examples/" &
      example & ".c " & cborObjsStr & " " & lib & " -pthread -Wl,-rpath,'$ORIGIN' -o " &
      outBin
    exec sanRunEnv(san) & outBin
