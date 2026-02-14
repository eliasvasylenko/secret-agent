{ self, pkgs, ... }:
pkgs.buildGoModule {
  pname = "secret-agent";
  version = "0.1";
  src = "${self}";
  vendorHash = "sha256-GtsPMsKXEboSrcyQHJZUthh7gONkp0AOs80AO3Nu9JE=";
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
