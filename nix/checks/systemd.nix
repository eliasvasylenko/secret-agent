{ self, pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "Create an instance of a systemd credential";

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
    # setup
    start_all()
    machine.wait_for_unit("sockets.target")

    # run test

    # asserts
  '';
}
