{ pkgs, ... }:
with pkgs;
mkShell {
  buildInputs = [ go ];
}
