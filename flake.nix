{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nix-vscode-extensions.url = "github:nix-community/nix-vscode-extensions";
    nix-vscode-extensions.inputs.nixpkgs.follows = "nixpkgs";
    gomod2nix = {
      url = "github:nix-community/gomod2nix";
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
          default = pkgs.buildGoModule {
            pname = "secret-agent";
            version = "0.1";
            src = ./.;
            vendorHash = "sha256-hXSKTS0vPY2psCG8zcivyS2hvm07LYx6dBHF73OJgYE=";
            env.CGO_ENABLED = 1;
            flags = [ "-trimpath" "-tags=linux"];
            ldflags = [
              "-s"
              "-w"
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
                    qwtel.sqlite-viewer
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
