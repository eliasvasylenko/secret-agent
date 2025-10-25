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
      self,
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
      forEachSystem =
        functions:
        nixpkgs.lib.genAttrs systems (
          system:
          nixpkgs.lib.mapAttrs (
            item: function:
            function {
              inherit system self;
              pkgs = import nixpkgs {
                inherit system;
                overlays = [ gomod2nix.overlays.default ];
              };
              extensions = nix-vscode-extensions.extensions.${system}.open-vsx;
            }
          ) functions
        );
    in
    {
      packages = forEachSystem {
        default = { system, ... }: self.packages.${system}.secret-agent;
        secret-agent = import ./nix/packages/secret-agent.nix;
        secret-ops = import ./nix/packages/secret-ops.nix;
      };
      # checks =
      #   let
      #     testFiles = builtins.attrNames (builtins.readDir ./nix/integrationTests);
      #     tests = nixpkgs.lib.attrsets.genAttrs testFiles (
      #       testFile: { pkgs, ... }: pkgs.testers.runNixOSTest (import ./nix/integrationTests/${testFile} self)
      #     );
      #   in
      #   forEachSystem tests;
      devShells = forEachSystem {
        default = { system, ... }: self.devShells.${system}.codium;
        codium = import ./nix/devShells/codium.nix;
      };
      nixosModules = {
        default = self.nixosModules.secret-agent;
        secret-agent = import ./nix/nixosModules/secret-agent.nix;
      };
    };
}
