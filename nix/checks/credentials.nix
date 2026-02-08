{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "Command credentials";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      # Create test users and groups
      users.groups.testgroup = {
        gid = 1001;
      };
      users.groups.testgroup2 = {
        gid = 1002;
      };
      users.users.testuser = {
        isSystemUser = true;
        uid = 1001;
        group = "testgroup";
        extraGroups = [ "testgroup2" ];
      };

      services.secret-agent = {
        enable = true;
        secrets = {
          test-secret = {
            create = {
              script = "${pkgs.writeShellApplication {
                name = "check-creds";
                runtimeInputs = [ pkgs.coreutils ];
                text = ''
                  echo "UID=$(id -u) GID=$(id -g) GROUPS=$(id -G)" > /tmp/cred-check.txt
                '';
              }}/bin/check-creds";
              credential = {
                uid = 1001;
                gid = 1001;
                groups = [ 1001 1002 ];
              };
            };
          };
          test-secret-no-creds = {
            create = "${pkgs.writeShellApplication {
              name = "check-creds-default";
              runtimeInputs = [ pkgs.coreutils ];
              text = ''
                echo "UID=$(id -u) GID=$(id -g) GROUPS=$(id -G)" > /tmp/cred-check-default.txt
              '';
            }}/bin/check-creds-default";
          };
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("sockets.target")

    with subtest("create secret with credentials"):
      # Create a secret instance - the command should run with testuser credentials
      machine.succeed("secret-agent create test-secret -r 'test with creds'")
      
      # Check that the command ran with the correct UID/GID
      credCheck = machine.succeed("cat /tmp/cred-check.txt").strip()
      assert "UID=1001" in credCheck, f"Expected UID=1001, got: {credCheck}"
      assert "GID=1001" in credCheck, f"Expected GID=1001, got: {credCheck}"
      assert "GROUPS=1001 1002" in credCheck or "GROUPS=1002 1001" in credCheck, \
        f"Expected groups to include 1001 and 1002, got: {credCheck}"

    with subtest("create secret without credentials"):
      # Create a secret instance without credentials - should run as root (default)
      machine.succeed("secret-agent create test-secret-no-creds -r 'test without creds'")
      
      # Check that the command ran with root credentials (UID=0)
      credCheckDefault = machine.succeed("cat /tmp/cred-check-default.txt").strip()
      assert "UID=0" in credCheckDefault, f"Expected UID=0 (root), got: {credCheckDefault}"
      assert "GID=0" in credCheckDefault, f"Expected GID=0 (root), got: {credCheckDefault}"
  '';
}
