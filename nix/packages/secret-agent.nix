{ pkgs, ... }:
pkgs.buildGoModule {
  pname = "secret-agent";
  version = "0.1";
  src = ../..;
  vendorHash = "sha256-Jc2/Uc4z0Sln/E+Bu6zZYAYWlQzg2iC0Hy9iSQaJDxM=";
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
