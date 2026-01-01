{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "List multiple instances of a secret";

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
    from datetime import datetime, timezone
    from re import search

    # setup
    startTime = datetime.now(timezone.utc)
    start_all()
    machine.wait_for_unit("sockets.target")

    # run test
    machine.succeed("secret-agent create db-creds")
    machine.succeed("secret-agent create db-creds")
    output = machine.succeed("secret-agent instances db-creds")

    # asserts
    endTime = datetime.now(timezone.utc)

    value = loads(output)
    for item in value:
      id = item.pop("id")
      assert search("^[a-zA-Z0-9-]+$", id), f"id '{id}' should be valid uuid"

      startedAt = datetime.fromisoformat(item["status"].pop("startedAt"))
      completedAt = datetime.fromisoformat(item["status"].pop("completedAt"))
      assert startTime <= startedAt <= completedAt <= endTime

    expected = loads("""[
      {
        "secret": {
          "name": "db-creds",
          "create": "echo created > /etc/creds"
        },
        "status": {
          "name": "create",
          "startedBy": "user"
        }
      },
      {
        "secret": {
          "name": "db-creds",
          "create": "echo created > /etc/creds"
        },
        "status": {
          "name": "create",
          "startedBy": "user"
        }
      }
    ]""")
    assert value == expected, f"value '{dumps(value)}' does not match expected '{dumps(expected)}'"
  '';
}
