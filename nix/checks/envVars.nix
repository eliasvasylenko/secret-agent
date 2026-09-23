# Integration test for passing environment variables into secrets. Create
# scripts receive env from config and from the caller.
# We verify:
# - secret gets configured environment and caller overrides (e.g. TEST1=test1)
{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "Passing environment variables into a secret";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;

        secrets.root = {
          environment = {
            VAR1 = "$TEST1";
            VAR2 = "var2";
            PATH = pkgs.lib.makeBinPath (with pkgs; [ coreutils ]);
          };
          create = ''
            mkdir -p "/etc/$SECRET"
            printenv > "/etc/$SECRET/$INSTANCE.cred"
          '';
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("sockets.target")

    def parse(output):
      env = {}
      for line in output.splitlines():
        if "=" in line:
          key, value = line.split("=", 1)
          env[key] = value
      for k in ["SHLVL", "PATH", "PWD", "_"]:
        env.pop(k, None)
      return env

    machine.succeed("TEST1=test1 TEST2=test2 secret-agent create root -r reason")

    with subtest("root env vars"):
      rootOutput = parse(machine.succeed("cat /etc/root/*.cred"))
      rootExpected = {
        "INSTANCE": rootOutput["INSTANCE"],
        "SECRET": "root",
        "FORCE": "false",
        "REASON": "reason",
        "VAR1": "test1",
        "VAR2": "var2",
        "STARTED_BY": "linux:root/0",
      }
      assert rootOutput == rootExpected, f"value '{rootOutput}' does not match expected '{rootExpected}'"
  '';
}
