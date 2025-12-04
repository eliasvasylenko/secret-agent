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
        function:
        nixpkgs.lib.genAttrs systems (
          system:
          function {
            inherit system self;
            root = ./.;
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ gomod2nix.overlays.default ];
            };
            extensions = nix-vscode-extensions.extensions.${system}.open-vsx;
          }
        );
      readNixFiles =
        path: args:
        let
          allFiles = builtins.attrNames (builtins.readDir path);
          nixFiles = builtins.filter (nixpkgs.lib.strings.hasSuffix ".nix") allFiles;
          nixFileNames = builtins.map (nixpkgs.lib.strings.removeSuffix ".nix") nixFiles;
        in
        nixpkgs.lib.attrsets.genAttrs nixFileNames (
          regularFile: import "${path}/${regularFile}.nix" args
        );
    in
    {
      overlays.default = (final: prev: { inherit (self.packages.${final.system}) secret-agent; });
      packages = forEachSystem (readNixFiles ./nix/packages);
      nixosModules = readNixFiles ./nix/nixosModules self;
      devShells = forEachSystem (readNixFiles ./nix/devShells);
      checks = forEachSystem (readNixFiles ./nix/checks);
    };
}
