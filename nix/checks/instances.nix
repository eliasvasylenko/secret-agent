# Integration test for secret instances. Create, activate, test, deactivate,
# destroy lifecycle and instance listing.
# We verify:
# - a successful operation enters the state of the same name
# - revision counts status writes: create completes at 2, each later success adds 2
# - list returns current instances, newest createdAt first
# - createdAt <= startedAt <= completedAt, and state.enteredAt equals completedAt
{ self, pkgs, ... }:
let
  expectedInstance = action: revision: {
    secret = {
      id = "db-creds";
      version = 1;
      create = "echo done create > /etc/creds";
      activate = "echo done activate > /etc/creds";
      deactivate = "echo done deactivate > /etc/creds";
      destroy = "echo done destroy > /etc/creds";
      test = "echo done test > /etc/creds";
    };
    revision = revision;
    state = {
      name = action;
    };
    operation = {
      secretId = "db-creds";
      name = action;
      createdBy = "root/0@system";
      startedBy = "root/0@system";
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
        operation = value["operation"]
        state = value["state"]
        createdAt = datetime.fromisoformat(operation.pop("createdAt"))
        startedAt = datetime.fromisoformat(operation.pop("startedAt"))
        completedAt = datetime.fromisoformat(operation.pop("completedAt"))
        enteredAt = datetime.fromisoformat(state.pop("enteredAt"))
        assert operation.pop("instanceId") == value["id"], f"operation instanceId does not match instance id: {value}"
        assert state["name"] == operation["name"], f"state {state['name']} does not match operation {operation['name']}"
        assert startTime <= createdAt <= startedAt <= completedAt <= endTime, f"unexpected operation times; violated condition: {startTime} <= {createdAt} <= {startedAt} <= {completedAt} <= {endTime}"
        assert enteredAt == completedAt, f"state enteredAt {enteredAt} does not match completedAt {completedAt}"

    def testAction(action, expected, id = ""):
      output = machine.succeed(f"""
        output=$(secret-agent {action} db-creds {id})
        echo $output
        diff \
          <(jq --sort-keys '.' {expected}) \
          <(echo $output | jq --sort-keys 'del(.id, .operation.instanceId, .state.enteredAt, .operation.createdAt, .operation.startedAt, .operation.completedAt)')
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
          <(echo $output | jq --sort-keys 'del(.[].id, .[].operation.instanceId, .[].state.enteredAt, .[].operation.createdAt, .[].operation.startedAt, .[].operation.completedAt)')
      """)
      testTimes(loads(output))
      return output

    with subtest("list none"):
      testList("${writeJSON []}")

    with subtest("create"):
      instance = testAction("create", "${writeJSON expectedInstance "create" 2}")
      id = loads(instance)["id"]

    with subtest("activate"):
      testAction("activate", "${writeJSON expectedInstance "activate" 4}", id)

    with subtest("test"):
      testAction("test", "${writeJSON expectedInstance "test" 6}", id)

    with subtest("deactivate"):
      testAction("deactivate", "${writeJSON expectedInstance "deactivate" 8}", id)

    with subtest("list single"):
      testList("${writeJSON [ (expectedInstance "deactivate" 8) ]}")

    with subtest("list multiple"):
      instance = machine.succeed("secret-agent create db-creds")
      id2 = loads(instance)["id"]
      testList("${
        writeJSON [
          (expectedInstance "create" 2)
          (expectedInstance "deactivate" 8)
        ]
      }")

    with subtest("destroy"):
      testAction("destroy", "${writeJSON expectedInstance "destroy" 10}", id)
      testAction("destroy", "${writeJSON expectedInstance "destroy" 4}", id2)
  '';
}
