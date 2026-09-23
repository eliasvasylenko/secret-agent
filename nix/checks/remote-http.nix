# HTTPS reverse-proxy e2e: CLI on X talks to the agent on B through Caddy.
# Caddy terminates TLS, dials the Unix socket, and asserts X-Secret-Agent-User.
# We verify:
# - catalog and create/activate over https://server
# - attach 101 (stdout) through Caddy's reverse_proxy
# - startedBy is the forwarded user, not Caddy's peercred
{ self, pkgs, ... }:
let
  certs = pkgs.runCommand "remote-http-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout $out/ca.key -out $out/ca.crt \
      -subj "/CN=secret-agent-test-CA"
    openssl req -newkey rsa:2048 -sha256 -nodes \
      -keyout $out/server.key -out $out/server.csr \
      -subj "/CN=server" \
      -addext "subjectAltName=DNS:server"
    openssl x509 -req -in $out/server.csr \
      -CA $out/ca.crt -CAkey $out/ca.key -CAcreateserial \
      -out $out/server.crt -days 3650 \
      -copy_extensions copy
  '';
in
pkgs.testers.runNixOSTest {
  name = "Remote HTTP";

  nodes.server =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      networking.firewall.allowedTCPPorts = [ 443 ];

      # Caddy may use PrivateTmp; the agent socket lives in the host /tmp.
      systemd.services.caddy.serviceConfig.PrivateTmp = false;

      users.users.caddy.extraGroups = [ "secret-agent" ];
      systemd.sockets.secret-agent.socketConfig = {
        SocketGroup = "secret-agent";
        SocketMode = "0660";
      };

      services.secret-agent = {
        enable = true;
        bindings = {
          users = {
            root = "admin";
            john = "admin";
          };
          forwardAuth.peers = [ "caddy" ];
        };
        secrets.remote = {
          create = ''
            echo remote-hello
          '';
          activate = "true";
          destroy = "true";
        };
      };

      services.caddy = {
        enable = true;
        globalConfig = ''
          auto_https off
        '';
        virtualHosts."https://server" = {
          extraConfig = ''
            tls ${certs}/server.crt ${certs}/server.key
            reverse_proxy unix//tmp/secret-agent.socket {
              header_up X-Secret-Agent-User john
              flush_interval -1
              transport http {
                versions 1.1
              }
            }
          '';
        };
      };

      system.stateVersion = "23.11";
    };

  nodes.client =
    { config, pkgs, ... }:
    {
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.secret-agent
      ];
      security.pki.certificateFiles = [ "${certs}/ca.crt" ];
      system.stateVersion = "23.11";
    };

  testScript = ''
    from json import loads

    start_all()
    server.wait_for_unit("sockets.target")
    server.wait_for_unit("caddy.service")
    server.wait_for_open_port(443)
    client.wait_until_succeeds("ping -c1 server")

    def remote(cmd):
      return client.succeed(f"secret-agent -a https://server {cmd}")

    def instance_json(output):
      return loads(output[output.index("{"):])

    with subtest("catalog over HTTPS"):
      secrets = remote("secrets")
      assert "remote" in secrets, f"secrets: {secrets}"

    with subtest("create over HTTPS includes attach stdout"):
      output = client.succeed("secret-agent -a https://server create remote </dev/null")
      assert "remote-hello" in output, f"stdout missing from: {output}"
      created = instance_json(output)
      assert created["status"]["startedBy"] == "http:john", f"startedBy: {created}"
      assert created["status"]["name"] == "create", f"op: {created}"
      instance_id = created["id"]

    with subtest("activate over HTTPS"):
      output = client.succeed(
        f"secret-agent -a https://server activate remote {instance_id} </dev/null"
      )
      activated = instance_json(output)
      assert activated["status"]["startedBy"] == "http:john", f"startedBy: {activated}"
      assert activated["status"]["name"] == "activate", f"op: {activated}"

    with subtest("local unix is still peercred, not the forward-auth header"):
      output = server.succeed("secret-agent create remote </dev/null")
      local = instance_json(output)
      assert local["status"]["startedBy"].startswith("linux:root/"), f"startedBy: {local}"
  '';
}
