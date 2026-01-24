{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "Passing environment variables into a secret";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;

        secrets.root =
          let
            createCred = pkgs.writeShellApplication {
              name = "createCred";
              runtimeInputs = [ pkgs.coreutils ];
              text = ''
                mkdir "/etc/$QNAME"
                printenv > "/etc/$QNAME/$ID.cred"
              '';
            };
          in
          {
            environment = {
              VAR1 = "$TEST1";
              VAR2 = "var2";
            };
            create = "${createCred}/bin/createCred";
            derive = {
              child1 = {
                environment = {
                  VAR1 = "override-$VAR1";
                  VAR2 = "override-$VAR2";
                };
                create = "${createCred}/bin/createCred";
              };
              child2 = {
                environment = {
                  VAR1 = "override-$VAR1";
                  VAR3 = "var3";
                  VAR4 = "$VAR2";
                };
                create = "${createCred}/bin/createCred";
              };
            };
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
        key, value = line.split("=", 1)
        env[key] = value
      del env["SHLVL"]
      del env["PATH"]
      del env["PWD"]
      del env["_"]
      return env

    machine.succeed("TEST1=test1 TEST2=test2 secret-agent create root -r reason")

    with subtest("root env vars"):
      rootOutput = parse(machine.succeed("cat /etc/root/*.cred"))
      rootExpected = {
        "ID": rootOutput["ID"],
        "NAME": "root",
        "FORCE": "false",
        "QID": f"root/{rootOutput["ID"]}",
        "QNAME": "root",
        "REASON": "reason",
        "VAR1": "test1",
        "VAR2": "var2",
        "STARTED_BY": "user",
      }
      assert rootOutput == rootExpected, f"value '{rootOutput}' does not match expected '{rootExpected}'"

    with subtest("child env vars 1"):
      child1Output = parse(machine.succeed("cat /etc/root/child1/*.cred"))
      child1Expected = {
        "ID": child1Output["ID"],
        "NAME": "child1",
        "FORCE": "false",
        "QID": f"root/child1/{child1Output["ID"]}",
        "QNAME": "root/child1",
        "REASON": "reason",
        "VAR1": "override-test1",
        "VAR2": "override-var2",
        "STARTED_BY": "user",
      }
      assert child1Output == child1Expected, f"value '{child1Output}' does not match expected '{child1Expected}'"

    with subtest("child env vars 2"):
      child2Output = parse(machine.succeed("cat /etc/root/child2/*.cred"))
      child2Expected = {
        "ID": child2Output["ID"],
        "NAME": "child2",
        "FORCE": "false",
        "QID": f"root/child2/{child2Output["ID"]}",
        "QNAME": "root/child2",
        "REASON": "reason",
        "VAR1": "override-test1",
        "VAR3": "var3",
        "VAR4": "var2",
        "STARTED_BY": "user",
      }
      assert child2Output == child2Expected, f"value '{child2Output}' does not match expected '{child2Expected}'"
  '';
}
