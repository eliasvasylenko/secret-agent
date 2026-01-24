{ self, pkgs, ... }:
let
  cred = {
    environment = {
      STAGING = "/etc/source";
      STORE = "/etc/credstore";
    };
    create = ''
      ${pkgs.coreutils}/bin/mkdir -p "$STAGING/$QNAME"
      ${pkgs.coreutils}/bin/cat < /dev/stdin > $STAGING/$QNAME/$ID
    '';
    activate = ''
      ${pkgs.coreutils}/bin/mkdir -p "$STORE"
      ${pkgs.coreutils}/bin/cp $STAGING/$QNAME/$ID $STORE/''${QNAME//\//.}
    '';
    deactivate = ''
      ${pkgs.coreutils}/bin/rm $STORE/''${QNAME//\//.}
    '';
    destroy = ''
      ${pkgs.coreutils}/bin/rm $STAGING/$QNAME/$ID
    '';
  };
  credEncrypted = cred // {
    environment = {
      STAGING = "/etc/source";
      STORE = "/etc/credstore.encrypted";
    };
    create = ''
      ${pkgs.coreutils}/bin/mkdir -p "$STAGING/$QNAME"
      ${pkgs.systemd}/bin/systemd-creds encrypt \
        --name ''${QNAME//\//.} \
        /dev/stdin \
        $STAGING/$QNAME/$ID
    '';
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

      systemd.services.credential-consumer = {
        description = "Credential consumer service";
        serviceConfig = {
          Type = "oneshot";
          Restart = "no";
          ExecStart = "${
            pkgs.writeShellApplication {
              name = "load-creds";
              runtimeInputs = with pkgs; [ coreutils ];
              text = ''
                echo loading available credentials...
                rm -f /etc/target/*
                mkdir -p /etc/target
                ls "$CREDENTIALS_DIRECTORY"
                cp "$CREDENTIALS_DIRECTORY/"* /etc/target || true
              '';
            }
          }/bin/load-creds";
          StandardOutput = "journal";
          StandardError = "journal";
          ImportCredential = [
            "simple.cred"
            "encrypted.cred"
          ];
        };
      };

      system.stateVersion = "23.11";
    };

  testScript = ''
    from json import loads

    start_all()
    machine.wait_for_unit("sockets.target")

    with subtest("no creds"):
      machine.succeed("systemctl start credential-consumer")
      machine.fail("rm /etc/target/*")
      instance = machine.succeed("secret-agent create simple")
      id1 = loads(instance)["id"]
      instance = machine.succeed("secret-agent create encrypted")
      id2 = loads(instance)["id"]
      machine.fail("rm /etc/target/*")

    with subtest("simple cred activated"):
      machine.succeed(f"secret-agent activate simple {id1}")
      machine.succeed("systemctl start credential-consumer")
      machine.succeed("diff /etc/target/simple.cred <(echo password123)")

    with subtest("simple cred deactivated"):
      machine.succeed(f"secret-agent deactivate simple {id1}")
      machine.succeed("systemctl start credential-consumer")
      machine.fail("rm /etc/target/*")

    with subtest("encrypted cred activated"):
      machine.succeed(f"secret-agent activate encrypted {id2}")
      machine.succeed("systemctl start credential-consumer")
      machine.succeed("diff /etc/target/encrypted.cred <(echo password123)")

    with subtest("encrypted cred deactivated"):
      machine.succeed(f"secret-agent deactivate encrypted {id2}")
      machine.succeed("systemctl start credential-consumer")
      machine.fail("rm /etc/target/*")
  '';
}
