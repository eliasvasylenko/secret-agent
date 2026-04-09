# Integration test for stdin, stdout, and stderr wiring through the API.
# We verify:
# - stdin piped on the CLI is forwarded to the create script
# - stdout and stderr from scripts are streamed back to the CLI
# - stdout is streamed incrementally (partial output arrives before command completes)
{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "Stdio wiring";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      environment.systemPackages = with pkgs; [
        coreutils
        gnugrep
      ];

      services.secret-agent = {
        enable = true;
        secrets.basic = {
          environment = {
            PATH = pkgs.lib.makeBinPath (with pkgs; [ coreutils ]);
          };
          create = ''
            cat > /tmp/stdin-received
            echo "stdout-hello"
            echo "stderr-hello" >&2
          '';
          destroy = "true";
        };
        secrets.streaming = {
          environment = {
            PATH = pkgs.lib.makeBinPath (with pkgs; [ coreutils ]);
          };
          create = ''
            echo -n "part1"
            cat /tmp/latch
            echo -n "part2"
          '';
          destroy = "true";
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("sockets.target")

    with subtest("stdin"):
      machine.succeed("echo -n 'test-input' | secret-agent create basic > /dev/null 2>/dev/null")
      received = machine.succeed("cat /tmp/stdin-received").strip()
      assert received == "test-input", f"stdin: got '{received}'"

    with subtest("stdout"):
      output = machine.succeed("secret-agent create basic 2>/dev/null")
      assert "stdout-hello" in output, f"stdout not found in: {output}"

    with subtest("stderr"):
      machine.succeed("secret-agent create basic > /dev/null 2>/tmp/stderr-output")
      stderr = machine.succeed("cat /tmp/stderr-output")
      assert "stderr-hello" in stderr, f"stderr not found in: {stderr}"

    with subtest("stdout streaming"):
      machine.succeed("mkfifo /tmp/latch")
      machine.succeed("secret-agent create streaming > /tmp/stream-out 2>/dev/null &")
      machine.wait_until_succeeds("grep -q part1 /tmp/stream-out")
      machine.fail("grep -q part2 /tmp/stream-out")
      machine.succeed("echo -n done > /tmp/latch")
      machine.wait_until_succeeds("grep -q done /tmp/stream-out")
      machine.wait_until_succeeds("grep -q part2 /tmp/stream-out")
  '';
}
