{ pkgs, root, ... }:
pkgs.buildGoModule {
  pname = "secret-agent";
  version = "0.1";
  src = root;
  vendorHash = "sha256-UPCJ/RSnANe2BMzHjo7WqBol+k+PW5PvUpXmFUcgyAI=";
  env.CGO_ENABLED = 1;
  flags = [
    "-trimpath"
    "-tags=linux"
  ];
  ldflags = [
    "-s"
    "-w"
  ];
}
