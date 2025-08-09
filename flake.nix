{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nix-vscode-extensions.url = "github:nix-community/nix-vscode-extensions";
    nix-vscode-extensions.inputs.nixpkgs.follows = "nixpkgs";
    gomod2nix = {
      url = "github:tweag/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      nix-vscode-extensions,
      gomod2nix,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        function:
        nixpkgs.lib.genAttrs systems (
          system:
          function ({
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ gomod2nix.overlays.default ];
            };
            extensions = nix-vscode-extensions.extensions.${system};
          })
        );
    in
    {
      packages = forAllSystems (
        {
          pkgs,
          ...
        }:
        {
          default = pkgs.buildGoApplication {
            name = "secret-agent";
            src = ./.;
            CGO_ENABLED = 0;
            flags = [ "-trimpath" ];
            ldflags = [
              "-s"
              "-w"
              "-extldflags -static"
            ];
          };
        }
      );
      devShells = forAllSystems (
        {
          pkgs,
          extensions,
        }:
        {
          default =
            with pkgs;
            mkShell {
              buildInputs = [
                (pkgs.vscode-with-extensions.override {
                  vscode = pkgs.vscodium;
                  vscodeExtensions = with extensions.open-vsx; [
                    golang.go
                    jnoortheen.nix-ide
                  ];
                })
                nil
                nixfmt-rfc-style
                go
              ];
            };
        }
      );
    };
}
