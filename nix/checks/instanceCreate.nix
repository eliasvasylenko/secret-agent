{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "Create an instance of a secret";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;
        secrets.db-creds = {
          create = "echo created > /etc/creds";
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    # setup
    start_all()
    machine.wait_for_unit("sockets.target")

    # run test
    machine.succeed("secret-agent create db-creds")
    output = machine.succeed("cat /etc/creds")

    # asserts
    expected = "created\n"
    assert output == expected, f"value '{output}' does not match expected '{expected}'"
  '';
}
