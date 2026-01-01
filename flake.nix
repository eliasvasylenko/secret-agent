{
  description = "Secret Agent";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nix-vscode-extensions = {
      url = "github:nix-community/nix-vscode-extensions";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }:
    let
      forEachSystem = self.lib.forEachSystem [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      lib = import ./nix/lib.nix self;
      packages = forEachSystem (self.lib.importNixFiles ./nix/packages);
      nixosModules = self.lib.importNixFiles ./nix/nixosModules self;
      devShells = forEachSystem (self.lib.importNixFiles ./nix/devShells);
      checks = forEachSystem (self.lib.importNixFiles ./nix/checks);
    };
}
