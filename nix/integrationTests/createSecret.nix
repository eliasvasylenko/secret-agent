{ nixosModules, ... }:
let
  writeJSON = nix: builtins.toFile "op.json" (builtins.toJSON nix);
  plans = writeJSON {
    
  };
in
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
    machine.succeed("ecret-agent rotate db-creds -p ${plans}")
    machine.fail("nc -U /tmp/secret-agent.socket")
  '';
}
