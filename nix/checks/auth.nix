# Integration test for linux auth. The server derives identity from Unix socket
# peer credentials and applies role mappings from the claims config.
# We verify:
# - user claims
# - group claims from peer cred gid
# - group claims from user groups
# - limited roles
# - 403 when unmapped
{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "Claim identity auth";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      # Allow test users and nobody to connect to the socket (peer creds are still used for auth)
      systemd.sockets.secret-agent.socketConfig.SocketMode = "0666";

      users.groups.testgroup = { gid = 1001; };
      users.groups.testgroup2 = { gid = 1002; };

      users.users.testuser = {
        isSystemUser = true;
        uid = 1001;
        group = "testgroup";
        extraGroups = [ "testgroup2" ];
      };
      users.users.grouptest = {
        isSystemUser = true;
        uid = 1002;
        group = "testgroup";
      };
      users.users.supptest = {
        isSystemUser = true;
        uid = 1003;
        group = "nogroup";
        extraGroups = [ "testgroup2" ];
      };
      users.users.peercredtest = {
        isSystemUser = true;
        uid = 1004;
        group = "nogroup";
      };

      services.secret-agent = {
        enable = true;
        roles = {
          admin.permissions = { all = "any"; };
          reader.permissions = { secrets = "any"; instances = "read"; };
        };
        claims = {
          users = {
            root = "admin";
            "1001" = "admin";
          };
          # Group claims: primary (peercred) and user's groups (GroupIds) are both matched
          groups = {
            "1001" = "reader";   # testgroup – primary for grouptest
            "1002" = "reader";   # testgroup2 – supplementary for testuser
          };
        };
        secrets = {
          test-secret = {
            create = "echo ok > /tmp/auth-test-secret";
          };
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("sockets.target")

    with subtest("root has admin role and can list secrets"):
      machine.succeed("secret-agent secrets | grep -q test-secret")

    with subtest("testuser has admin role (from user claim) and can create instance"):
      machine.succeed("su -s ${pkgs.bash}/bin/bash testuser -c 'secret-agent create test-secret -r auth-test'")

    with subtest("nobody has no role and gets 403 on list secrets"):
      output = machine.fail("su -s ${pkgs.bash}/bin/bash nobody -c 'secret-agent secrets' 2>&1")
      assert "403" in output or "Forbidden" in output or "forbidden" in output, \
        f"Expected 403/Forbidden in output, got: {output}"

    with subtest("reader role can list but not create"):
      machine.succeed("su -s ${pkgs.bash}/bin/bash grouptest -c 'secret-agent secrets' | grep -q test-secret")
      output = machine.fail("su -s ${pkgs.bash}/bin/bash grouptest -c 'secret-agent create test-secret -r no' 2>&1")
      assert "403" in output or "Forbidden" in output or "forbidden" in output, \
        f"Expected 403 when reader creates instance, got: {output}"

    with subtest("peercred group is authorised (grouptest gets reader from primary group only)"):
      machine.succeed("su -s ${pkgs.bash}/bin/bash grouptest -c 'secret-agent secrets' | grep -q test-secret")

    with subtest("user supplementary groups are authorised (supptest gets reader from testgroup2 only)"):
      machine.succeed("su -s ${pkgs.bash}/bin/bash supptest -c 'secret-agent secrets' | grep -q test-secret")
      output = machine.fail("su -s ${pkgs.bash}/bin/bash supptest -c 'secret-agent create test-secret -r no' 2>&1")
      assert "403" in output or "Forbidden" in output or "forbidden" in output, \
        f"Expected 403 when reader creates instance, got: {output}"

    with subtest("peer cred gid is used when it differs from user primary group"):
      # peercredtest has primary group nogroup (100), is not in testgroup2. Run with
      # runuser -g testgroup2 so the process has gid=1002; only that peer cred gid
      # (not the user's GroupIds()) supplies group 1002, so they get reader.
      machine.succeed("runuser -u peercredtest -g testgroup2 secret-agent secrets | grep -q test-secret")
  '';
}
