{
  description = "cage — minimal SSH-based secrets manager (age + SSH keys)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };

          staticGoBuild = drv: pkgs.stdenv.mkDerivation {
            inherit drv;

            buildFlagsArray = [
              "CGO_ENABLED=0"
              "GOOS=${drv.goos or ""}"
              "GOARCH=${drv.goarch or ""}"
            ];

            NIX_CFLAGS_COMPILE = "";
            NIX_LDFLAGS = "";
          };
        in
        rec {
          cage = pkgs.buildGoModule rec {
            pname = "cage";
            version = "0.1.0";

            src = self;

            subPackages = [ "." ];

            #vendorHash = nixpkgs.lib.fakeHash;
            vendorHash = "sha256-W5bAU8TjiUA87uuZ4/WYoZAiJzq8/4f3kEW2IbGjoUY=";

            buildFlagsArray = [
              "CGO_ENABLED=0"
            ];

            dontUseCgo = true;

            go = pkgs.go_1_25;

            meta = with pkgs.lib; {
              description = "Minimal SSH-based secrets manager (age + existing SSH Ed25519 keys), fully static";
              platforms = platforms.unix;
            };
          };

          default = cage;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/cage";
        };
      });

      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gopls
              pkgs.golangci-lint
            ];
          };
        });

      overlays.default = final: prev: {
        cage = self.packages.${final.stdenv.hostPlatform.system}.default;
      };
    };
}
