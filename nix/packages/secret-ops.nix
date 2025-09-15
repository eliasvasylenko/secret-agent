{ pkgs, ... }:
pkgs.buildGoModule {
  pname = "secret-ops";
  version = "0.1";
  src = ../../cmd/secret-ops;
  vendorHash = "sha256-hXSKTS0vPY2psCG8zcivyS2hvm07LYx6dBHF73OJgYE=";
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
