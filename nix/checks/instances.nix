{ self, pkgs, ... }:
let
  expectedInstance = action: {
    secret = {
      name = "db-creds";
      create = "echo done create > /etc/creds";
      activate = "echo done activate > /etc/creds";
      deactivate = "echo done deactivate > /etc/creds";
      destroy = "echo done destroy > /etc/creds";
      test = "echo done test > /etc/creds";
    };
    status = {
      name = action;
      startedBy = "user";
    };
  };
  expectedInstances = builtins.map expectedInstance;
  writeJSON = function: argument: pkgs.writeText "expected" (builtins.toJSON (function argument));
in
pkgs.testers.runNixOSTest {
  name = "Activate an instance of a secret";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      environment.systemPackages = with pkgs; [
        jq
      ];

      services.secret-agent = {
        enable = true;
        secrets.db-creds = {
          create = "echo done create > /etc/creds";
          activate = "echo done activate > /etc/creds";
          deactivate = "echo done deactivate > /etc/creds";
          destroy = "echo done destroy > /etc/creds";
          test = "echo done test > /etc/creds";
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    from json import loads
    from datetime import datetime, timezone

    # setup
    start_all()
    machine.wait_for_unit("sockets.target")
    startTime = datetime.now(timezone.utc)

    def testAction(action, expected, id = ""):
      output = machine.succeed(f"""
        output=$(secret-agent {action} db-creds {id})
        echo $output
        diff \
          <(jq --sort-keys '.' {expected}) \
          <(echo $output | jq --sort-keys 'del(.id, .status.startedAt, .status.completedAt)')
      """)
      machine.succeed(f"diff /etc/creds <(echo done {action})")
      return output

    def testList(expected):
      endTime = datetime.now(timezone.utc)
      output = machine.succeed(f"""
        output=$(secret-agent instances db-creds)
        echo $output
        diff \
          <(jq --sort-keys '.' {expected}) \
          <(echo $output | jq --sort-keys 'del(.[].id, .[].status.startedAt, .[].status.completedAt)')
      """)
      value = loads(output)
      for item in value:
        startedAt = datetime.fromisoformat(item["status"].pop("startedAt"))
        completedAt = datetime.fromisoformat(item["status"].pop("completedAt"))
        assert startTime <= startedAt <= completedAt <= endTime, "unexpected startedAt and completedAt times"

    with subtest("list none"):
      testList("${writeJSON expectedInstances [ ]}")

    with subtest("create"):
      instance = testAction("create", "${writeJSON expectedInstance "create"}")
      id = loads(instance)["id"]

    with subtest("activate"):
      testAction("activate", "${writeJSON expectedInstance "activate"}", id)

    with subtest("test"):
      testAction("test", "${writeJSON expectedInstance "test"}", id)

    with subtest("deactivate"):
      testAction("deactivate", "${writeJSON expectedInstance "deactivate"}", id)

    with subtest("list single"):
      testList("${writeJSON expectedInstances [ "deactivate" ]}")

    with subtest("list multiple"):
      instance = machine.succeed("secret-agent create db-creds")
      id2 = loads(instance)["id"]
      testList("${
        writeJSON expectedInstances [
          "create"
          "deactivate"
        ]
      }")

    with subtest("destroy"):
      testAction("destroy", "${writeJSON expectedInstance "destroy"}", id)
      testAction("destroy", "${writeJSON expectedInstance "destroy"}", id2)
  '';
}
