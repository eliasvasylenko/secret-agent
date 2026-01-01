self: with self.inputs.nixpkgs; rec {
  forEachSystem =
    systems: function:
    lib.genAttrs systems (
      system:
      function {
        inherit system self;
        pkgs = legacyPackages.${system};
      }
    );

  readNixFiles =
    path:
    let
      allFiles = builtins.attrNames (lib.filterAttrs (n: v: v == "regular") (builtins.readDir path));
      nixFiles = builtins.filter (lib.strings.hasSuffix ".nix") allFiles;
      nixFileNames = builtins.map (lib.strings.removeSuffix ".nix") nixFiles;
    in
    lib.genAttrs nixFileNames (regularFile: "${path}/${regularFile}.nix");

  importNixFiles = path: args: lib.mapAttrs (name: file: import file args) (readNixFiles path);

  readDirs =
    path: function:
    let
      allDirs = builtins.attrNames (lib.filterAttrs (n: v: v == "directory") (builtins.readDir path));
    in
    lib.genAttrs allDirs function;
}
