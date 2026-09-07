# Integration test for stdin, stdout, and stderr wiring through the API.
# We verify:
# - stdin piped on the CLI is forwarded to the create script
# - stdout and stderr from scripts are streamed back to the CLI
# - stdout is streamed incrementally (partial output arrives before command completes)
# - stdin arrives in multiple writes (chunked over process/io)
# - stdin and stdout are exchanged concurrently (interleaved)
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
        secrets.stdin-chunks = {
          environment = {
            PATH = pkgs.lib.makeBinPath (with pkgs; [ coreutils ]);
          };
          create = ''
            head -c 10 > /tmp/stdin-chunked
          '';
          destroy = "true";
        };
        secrets.interleaved = {
          environment = {
            PATH = pkgs.lib.makeBinPath (with pkgs; [ coreutils ]);
          };
          create = ''
            echo -n "before-read"
            head -c 7 > /tmp/interleaved-stdin
            echo -n "after-read:"
            cat /tmp/interleaved-stdin
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

    with subtest("stdin in chunks"):
      machine.succeed(
        "(printf hello; sleep 0.5; printf world) | secret-agent create stdin-chunks > /dev/null 2>/dev/null"
      )
      machine.wait_until_succeeds("test -f /tmp/stdin-chunked")
      received = machine.succeed("cat /tmp/stdin-chunked").strip()
      assert received == "helloworld", f"chunked stdin: got '{received}'"

    with subtest("interleaved stdin and stdout"):
      machine.succeed("rm -f /tmp/interleaved-out")
      machine.succeed("mkfifo /tmp/interleaved-in")
      # Opening a fifo O_RDONLY via "< fifo" blocks until a writer exists; use
      # O_RDWR (exec N<> fifo) so the shell can start secret-agent before payload.
      machine.succeed(
        "bash -c 'exec 3<> /tmp/interleaved-in; secret-agent create interleaved 0<&3 > /tmp/interleaved-out 2>/dev/null & exec 3>&-'"
      )
      machine.wait_until_succeeds("grep -q before-read /tmp/interleaved-out")
      machine.fail("grep -q after-read /tmp/interleaved-out")
      machine.succeed("printf 'payload' > /tmp/interleaved-in")
      machine.wait_until_succeeds("grep -q 'after-read:payload' /tmp/interleaved-out")
      on_disk = machine.succeed("cat /tmp/interleaved-stdin").strip()
      assert on_disk == "payload", f"script stdin file: got '{on_disk}'"
  '';
}
