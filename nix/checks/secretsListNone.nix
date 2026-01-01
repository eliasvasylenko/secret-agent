{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "List no secrets";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    from json import loads, dumps

    # setup
    start_all()
    machine.wait_for_unit("sockets.target")

    # run test
    output = machine.succeed("secret-agent secrets")

    # asserts
    value = loads(output)
    expected = loads("[]")
    assert value == expected, f"value '{dumps(value)}' does not match expected '{dumps(expected)}'"
  '';
}
