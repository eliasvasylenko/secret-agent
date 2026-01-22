{ self, pkgs, ... }:
let
  cred = {
    environment = {
      STAGING = "/etc/credstore/secret-agent";
      STORE = "/etc/credstore";
    };
    create = ''
      ${pkgs.coreutils}/bin/mkdir -p "$STAGING/$QNAME"
      cat <&1 >$STAGING/$QNAME/$ID
    '';
    activate = ''
      ${pkgs.coreutils}/bin/cp $STAGING/$QNAME/$ID $STORE/$\{QNAME//\//.}
    '';
    deactivate = ''
      ${pkgs.coreutils}/bin/rm $STORE/$\{QNAME//\//.}
    '';
    destroy = ''
      ${pkgs.coreutils}/bin/rm $STAGING/$QNAME/$ID
    '';
  };
  credEncrypted = cred // {
    environment = {
      STAGING = "/etc/credstore.encrypted/secret-agent";
      STORE = "/etc/credstore.encrypted";
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "Create an instance of a systemd credential";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.secret-agent ];

      services.secret-agent = {
        enable = true;

        secrets.simple = {
          create = "echo password123";
          derive.cred = cred;
        };

        secrets.encrypted = {
          create = "echo password123";
          derive.cred = credEncrypted;
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
