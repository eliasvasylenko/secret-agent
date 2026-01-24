{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "List multiple secrets";

  nodes.none =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;
      };

      system.stateVersion = "23.11";
    };

  nodes.single =
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

  nodes.multiple =
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

    start_all()
    none.wait_for_unit("sockets.target")
    single.wait_for_unit("sockets.target")
    multiple.wait_for_unit("sockets.target")

    with subtest("list none"):
      output = none.succeed("secret-agent secrets")
      value = loads(output)
      expected = loads("[]")
      assert value == expected, f"value '{dumps(value)}' does not match expected '{dumps(expected)}'"

    with subtest("list single"):
      output = single.succeed("secret-agent secrets")
      value = loads(output)
      expected = loads("""[
        {
          "name": "db-creds",
          "create": "echo created > /etc/creds"
        }
      ]""")
      assert value == expected, f"value '{dumps(value)}' does not match expected '{dumps(expected)}'"

    with subtest("list multiple"):
      output = multiple.succeed("secret-agent secrets")
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
