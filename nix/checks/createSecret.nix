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
          create = "echo hello, world > /etc/creds";
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("sockets.target")
    machine.succeed("secret-agent create db-creds")
    output = machine.succeed("cat /etc/creds")
    ${(pkgs.callPackage ./helpers { }).matchString "output" "hello, world\n"}
  '';
}
