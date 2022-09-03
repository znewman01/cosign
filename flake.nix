{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix.url = "github:tweag/gomod2nix";
    gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
    nix-filter.url = "github:numtide/nix-filter";
  };
  outputs = { nixpkgs, flake-utils, gomod2nix, nix-filter, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ gomod2nix.overlays.default ];
        };
      in rec {
        packages.default = pkgs.buildGoApplication {
          pname = "cosign";
          version = "v1.11.1";
          src = nix-filter.lib.filter {
            root = ./.;
            include = [ ./cmd ./internal ./pkg  ./test ./go.mod ./go.sum ];
          };
          modules = ./gomod2nix.toml;
          preCheck = ''
            # test all paths
            unset subPackages
            rm pkg/cosign/tlog_test.go # Require network access
            rm pkg/cosign/verify_test.go # Require network access
          '';
        };
        # apps = rec {
        #   cosign = flake-utils.lib.mkApp {
        #     name = "cosign";
        #     drv = packages.default;
        #   };
	#   default = cosign;
        # };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs;
            [
              nixfmt
              gocode
              gore
              gomodifytags
              gopls
              go-symbols
              gopkgs
              go-outline
              gotests
              gotools
              golangci-lint
              gomod2nix.packages.${system}.default
              nodePackages.bash-language-server
              jq
              yq-go
              pcsclite
	      step-cli
            ] ++ packages.default.nativeBuildInputs;
        };
      });
}
