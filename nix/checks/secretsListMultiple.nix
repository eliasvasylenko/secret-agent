{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "List multiple secrets";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;
        secrets.db-creds = {
          create = "echo created > /etc/creds";
        };
        secrets.extra-creds = {
          create = "init-creds";
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    from json import loads, dumps

    # setup
    start_all()
    machine.wait_for_unit("sockets.target")

    # run test
    output = machine.succeed("secret-agent secrets")

    # asserts
    value = {item["name"]: item for item in loads(output)}
    expected = loads("""{
      "db-creds": {
        "name": "db-creds",
        "create": "echo created > /etc/creds"
      },
      "extra-creds": {
        "name": "extra-creds",
        "create": "init-creds"
      }
    }""")
    assert value == expected, f"value '{dumps(value)}' does not match expected '{dumps(expected)}'"
  '';
}
