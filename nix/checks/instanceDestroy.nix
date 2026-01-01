{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "Destroy an instance of a secret";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;
        secrets.db-creds = {
          create = "echo created > /etc/creds";
          destroy = "echo destroyed > /etc/creds";
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    from json import loads

    # setup
    start_all()
    machine.wait_for_unit("sockets.target")

    # run test
    instance = machine.succeed("secret-agent create db-creds")
    id = loads(instance)["id"]
    machine.succeed(f"secret-agent destroy db-creds {id}")
    output = machine.succeed("cat /etc/creds")

    # asserts
    expected = "destroyed\n"
    assert output == expected, f"value '{output}' does not match expected '{expected}'"
  '';
}
