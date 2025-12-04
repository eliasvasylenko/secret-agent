{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "list no secrets";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("sockets.target")
    output = machine.succeed("secret-agent secrets")
    ${(pkgs.callPackage ./helpers { }).matchJson "output" [ ]}
  '';
}
