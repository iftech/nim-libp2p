{
  description = "nim-libp2p dev shell flake";

  nixConfig = {
    extra-substituters = [ "https://nix-cache.status.im/" ];
    extra-trusted-public-keys = [
      "nix-cache.status.im-1:x/93lOfLU+duPplwMSBR+OlY4+mo+dCN7n0mr4oPwgY="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux" "aarch64-linux" "armv7a-linux"
        "x86_64-darwin" "aarch64-darwin"
        "x86_64-windows"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [
          (final: prev: {
            nim-unwrapped-2_2 = prev.nim-unwrapped-2_2.overrideAttrs (old: {
              version = "2.2.12";
              patches = map (patch:
                if builtins.baseNameOf patch == "extra-mangling-2.patch"
                then ./nix/nim-extra-mangling.patch
                else patch
              ) old.patches;
              src = final.fetchurl {
                url = "https://nim-lang.org/download/nim-2.2.12.tar.xz";
                hash = "sha256-Jjmgal6np/z1ffHn4e9NGyvuWMesm9ANvSqlvqHlpWo=";
              };
            });
          })
        ];
        config = {
          android_sdk.accept_license = true;
          allowUnfreePredicate = pkg:
            let name = nixpkgs.lib.getName pkg;
            in nixpkgs.lib.any (prefix: nixpkgs.lib.hasPrefix prefix name) [
              "android"
              "build-tools"
              "cmdline-tools"
              "ndk"
              "platform-tools"
              "platforms"
              "tools"
            ];
        };
      };
    in {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          androidSupported = pkgs.stdenv.hostPlatform.isLinux || pkgs.stdenv.hostPlatform.isDarwin;
          iosSupported = pkgs.stdenv.hostPlatform.isDarwin;
          androidArm64 = import ./nix/cbind-ffi-android.nix {
            inherit pkgs;
            src = ./.;
            abi = "arm64-v8a";
            androidTriple = "aarch64-linux-android";
            nimCpu = "arm64";
          };
          androidX86 = import ./nix/cbind-ffi-android.nix {
            inherit pkgs;
            src = ./.;
            abi = "x86_64";
            androidTriple = "x86_64-linux-android";
            nimCpu = "amd64";
          };
          iosArm64 = import ./nix/cbind-ffi-ios.nix {
            inherit pkgs;
            src = ./.;
            targetName = "arm64";
            sdk = "iphoneos";
            platformName = "IOS";
            targetTriple = "arm64-apple-ios13.0";
          };
          iosSimulatorArm64 = import ./nix/cbind-ffi-ios.nix {
            inherit pkgs;
            src = ./.;
            targetName = "simulator-arm64";
            sdk = "iphonesimulator";
            platformName = "IOSSIMULATOR";
            targetTriple = "arm64-apple-ios13.0-simulator";
          };
        in {
          default = import ./nix/default.nix {
            inherit pkgs;
            src = ./.;
          };

          cbind = import ./nix/cbind.nix {
            inherit pkgs;
            src = ./.;
          };
        } // pkgs.lib.optionalAttrs androidSupported {
          cbind-ffi-android-arm64-v8a = androidArm64;

          cbind-ffi-android-x86_64 = androidX86;

          cbind-ffi-android = pkgs.runCommand "nim-libp2p-cbind-ffi-android" { } ''
            mkdir -p $out/android/arm64-v8a $out/android/x86_64
            cp -R ${androidArm64}/. $out/android/arm64-v8a/
            cp -R ${androidX86}/.   $out/android/x86_64/
          '';
        } // pkgs.lib.optionalAttrs iosSupported {
          cbind-ffi-ios-arm64 = iosArm64;

          cbind-ffi-ios-simulator-arm64 = iosSimulatorArm64;

          cbind-ffi-ios = pkgs.runCommand "nim-libp2p-cbind-ffi-ios" { } ''
            mkdir -p $out/ios/arm64 $out/ios/simulator-arm64
            cp -R ${iosArm64}/.          $out/ios/arm64/
            cp -R ${iosSimulatorArm64}/. $out/ios/simulator-arm64/
          '';
        }
      );

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in {
          default = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.nim-2_2
              pkgs.nimble
              pkgs.makeWrapper
            ];
          };
        }
      );
    };
}
