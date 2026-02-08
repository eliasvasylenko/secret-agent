{ self, pkgs, ... }:
let
  expectedInstance = action: number: {
    secret = {
      name = "db-creds";
      create = "echo done create > /etc/creds";
      activate = "echo done activate > /etc/creds";
      deactivate = "echo done deactivate > /etc/creds";
      destroy = "echo done destroy > /etc/creds";
      test = "echo done test > /etc/creds";
    };
    status = {
      operationNumber = number;
      name = action;
      startedBy = "linux:root/0";
    };
  };
  writeJSON =
    item:
    if builtins.isFunction item then
      argument: writeJSON (item argument)
    else
      pkgs.writeText "expected" (builtins.toJSON item);
in
pkgs.testers.runNixOSTest {
  name = "Secret instances";

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
    from datetime import datetime

    start_all()
    machine.wait_for_unit("sockets.target")

    def date():
      return datetime.fromisoformat(machine.succeed("date '+%Y-%m-%dT%H:%M:%S.%6NZ'").strip())

    startTime = date()

    def testTimes(values):
      endTime = date()
      for value in values:
        startedAt = datetime.fromisoformat(value["status"].pop("startedAt"))
        completedAt = datetime.fromisoformat(value["status"].pop("completedAt"))
        assert startTime <= startedAt <= completedAt <= endTime, f"unexpected startedAt and completedAt times; violated condition: {startTime} <= {startedAt} <= {completedAt} <= {endTime}"

    def testAction(action, expected, id = ""):
      output = machine.succeed(f"""
        output=$(secret-agent {action} db-creds {id})
        echo $output
        diff \
          <(jq --sort-keys '.' {expected}) \
          <(echo $output | jq --sort-keys 'del(.id, .status.startedAt, .status.completedAt)')
      """)
      machine.succeed(f"diff /etc/creds <(echo done {action})")
      testTimes([loads(output)])
      return output

    def testList(expected):
      output = machine.succeed(f"""
        output=$(secret-agent instances db-creds)
        echo $output
        diff \
          <(jq --sort-keys '.' {expected}) \
          <(echo $output | jq --sort-keys 'del(.[].id, .[].status.startedAt, .[].status.completedAt)')
      """)
      testTimes(loads(output))
      return output

    with subtest("list none"):
      testList("${writeJSON []}")

    with subtest("create"):
      instance = testAction("create", "${writeJSON expectedInstance "create" 1}")
      id = loads(instance)["id"]

    with subtest("activate"):
      testAction("activate", "${writeJSON expectedInstance "activate" 2}", id)

    with subtest("test"):
      testAction("test", "${writeJSON expectedInstance "test" 3}", id)

    with subtest("deactivate"):
      testAction("deactivate", "${writeJSON expectedInstance "deactivate" 4}", id)

    with subtest("list single"):
      testList("${writeJSON [ (expectedInstance "deactivate" 4) ]}")

    with subtest("list multiple"):
      instance = machine.succeed("secret-agent create db-creds")
      id2 = loads(instance)["id"]
      testList("${
        writeJSON [
          (expectedInstance "create" 5)
          (expectedInstance "deactivate" 4)
        ]
      }")

    with subtest("destroy"):
      testAction("destroy", "${writeJSON expectedInstance "destroy" 6}", id)
      testAction("destroy", "${writeJSON expectedInstance "destroy" 7}", id2)
  '';
}
