{ pkgs, extensions, ... }:
with pkgs;
mkShell {
  buildInputs = [
    (pkgs.vscode-with-extensions.override {
      vscode = pkgs.vscodium;
      vscodeExtensions = with extensions; [
        golang.go
        jnoortheen.nix-ide
        qwtel.sqlite-viewer
      ];
    })
    nil
    nixfmt-rfc-style
    go
  ];
}
