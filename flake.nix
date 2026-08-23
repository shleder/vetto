{
  description = "vetto — daemon-less sandbox and audit layer for AI coding agents";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "vetto";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.pkg-config ];
            doCheck = pkgs.stdenv.buildPlatform == pkgs.stdenv.hostPlatform;
            meta = with pkgs.lib; {
              description = "Daemon-less sandbox and audit layer for AI coding agents";
              homepage = "https://github.com/shleder/vetto";
              license = licenses.asl20;
              mainProgram = "vetto";
              platforms = platforms.linux ++ platforms.darwin;
            };
          };
        });
    };
}
