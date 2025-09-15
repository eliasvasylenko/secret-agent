{ nixosModules, ... }:
{
  name = "create a secret";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;
      };

      secret-agent.db-creds = {
        create = "echo hello, world > /etc/message";
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    machine.wait_for_unit("default.target")
    machine.succeed("nc -U /tmp/secret-agent.socket")
    machine.fail("nc -U /tmp/secret-agent.socket")
  '';
}
