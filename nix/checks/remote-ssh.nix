# SSH stdio e2e on host services.openssh. Match User secret-agent only.
# Nix-pinned keys (alice) and an activate-style fragment (bob) are both accepted.
{ self, pkgs, ... }:
let
  inherit (pkgs) lib;
  pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.secret-agent;
  keys = pkgs.runCommand "remote-ssh-keys" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir -p $out
    ssh-keygen -q -t ed25519 -N "" -C alice -f $out/id_alice
    ssh-keygen -q -t ed25519 -N "" -C bob -f $out/id_bob
    ssh-keygen -q -t ed25519 -N "" -C jane -f $out/id_jane
  '';
  installBobFragment = pkgs.writeShellScript "install-bob-fragment" ''
    set -euo pipefail
    install -d -m 755 /var/lib/secret-agent/ssh/authorized_keys.d
    {
      printf 'restrict,command="%s" ' ${lib.escapeShellArg "${pkg}/bin/secret-agent dial-stdio -u bob"}
      cat ${keys}/id_bob.pub
    } > /var/lib/secret-agent/ssh/authorized_keys.d/bob
    chmod 644 /var/lib/secret-agent/ssh/authorized_keys.d/bob
  '';
in
pkgs.testers.runNixOSTest {
  name = "Remote SSH";

  nodes.server =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.openssh.enable = true;

      users.users.jane = {
        isNormalUser = true;
        openssh.authorizedKeys.keyFiles = [ "${keys}/id_jane.pub" ];
      };

      services.secret-agent = {
        enable = true;
        ssh.enable = true;
        ssh.shared.alice.keyFiles = [ "${keys}/id_alice.pub" ];
        bindings.users = {
          root = "admin";
          alice = "admin";
          bob = "admin";
        };
        secrets.remote = {
          create = ''
            echo remote-hello
          '';
          activate = "true";
          destroy = "true";
        };
      };

      system.stateVersion = "23.11";
    };

  nodes.client =
    { config, pkgs, ... }:
    {
      environment.systemPackages = [
        pkgs.openssh
        pkg
      ];
      system.activationScripts.remote-ssh-key.text = ''
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        cp ${keys}/id_alice /root/.ssh/id_ed25519
        cp ${keys}/id_bob /root/.ssh/id_bob
        cp ${keys}/id_jane /root/.ssh/id_jane
        chmod 600 /root/.ssh/id_ed25519 /root/.ssh/id_bob /root/.ssh/id_jane
        cat >> /root/.ssh/config <<'EOF'
        Host server-bob
          HostName server
          User secret-agent
          IdentityFile /root/.ssh/id_bob
          IdentitiesOnly yes
        EOF
        chmod 600 /root/.ssh/config
      '';
      system.stateVersion = "23.11";
    };

  testScript = ''
    from json import loads

    start_all()
    server.wait_for_unit("sockets.target")
    server.wait_for_unit("sshd.service")
    server.wait_for_open_port(22)
    client.wait_until_succeeds("ping -c1 server")
    client.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
    client.wait_until_succeeds("ssh-keyscan server >> /root/.ssh/known_hosts")

    def instance_json(output):
      return loads(output[output.index("{"):])

    with subtest("other users keep a shell"):
      output = client.succeed(
        "ssh -o BatchMode=yes -i /root/.ssh/id_jane jane@server echo pwned </dev/null"
      )
      assert "pwned" in output, f"jane should still have a shell: {output}"

    with subtest("shared user forced command is not a shell"):
      status, output = client.execute(
        "ssh -o BatchMode=yes secret-agent@server echo pwned </dev/null"
      )
      assert "pwned" not in output, f"shell ran: {output}"
      assert status != 0, f"forced command should not look like a shell: {output}"

    with subtest("shared user forwarding disabled"):
      status, output = client.execute(
        "ssh -o BatchMode=yes -o ExitOnForwardFailure=yes "
        "-R 9999:127.0.0.1:1 secret-agent@server true </dev/null 2>&1"
      )
      assert status != 0, f"forwarding succeeded: {output}"
      assert "Permission denied" not in output, f"auth failed: {output}"
      assert "forwarding" in output.lower(), f"expected forwarding denial: {output}"

    with subtest("nix-pinned shared key injects name header"):
      output = client.succeed(
        "secret-agent -a ssh://secret-agent@server create remote </dev/null"
      )
      shared = instance_json(output)
      assert "remote-hello" in output, f"stdout missing from: {output}"
      assert shared["status"]["startedBy"] == "http:alice", f"startedBy: {shared}"

    with subtest("agent fragment is a second sshd source"):
      server.succeed("${installBobFragment}")
      output = client.succeed(
        "secret-agent -a ssh://secret-agent@server-bob create remote </dev/null"
      )
      bob = instance_json(output)
      assert bob["status"]["startedBy"] == "http:bob", f"startedBy: {bob}"

    with subtest("local unix is still peercred"):
      output = server.succeed("secret-agent create remote </dev/null")
      local = instance_json(output)
      assert local["status"]["startedBy"].startswith("linux:root/"), f"startedBy: {local}"
  '';
}
