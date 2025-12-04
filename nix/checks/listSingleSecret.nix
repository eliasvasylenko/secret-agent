{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "list a single secret";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;
        secrets.db-creds = {
          create = "echo hello, world > /etc/message";
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("sockets.target")
    output = machine.succeed("secret-agent secrets")
    ${(pkgs.callPackage ./helpers { }).matchJson "output" [
      {
        id = "db-creds";
        create = "echo hello, world > /etc/message";
      }
    ]}
  '';
}
