{
  packages,
  ...
}:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  # Make the options for a secret command
  mkCommandOptions =
    purpose:
    lib.mkOption {
      description = "Command to ${purpose}.";
      type = with lib.types; nullOr str;
      default = null;
    };

  # Make the options for provisioning an encrypted secret to be mounted by systemd-creds
  serviceOptions = name: {
    enable = lib.mkEnableOption "service credential";

    suppressUnencrypted = lib.mkOption {
      description = ''
        Suppress existing unencrypted LoadCredential options.
        This is sometimes needed in case of collision.
      '';
      default = false;
      type = with lib.types; bool;
    };

    name = lib.mkOption {
      description = "The name of the credential when encrypted with systemd-creds.";
      default = name;
      type = with lib.types; str;
    };

    bindPath = lib.mkOption {
      description = ''
        Path to mount the credential file privately to the service.
        This is sometimes needed if the secret path is configured in a
        context where we can't expand env vars or systemd specifiers.
      '';
      default = null;
      type = with lib.types; nullOr str;
    };
  };

  # Make the options for provisioning the secret remotely
  remoteOptions = name: {
    enable = lib.mkEnableOption "remote secret";

    name = lib.mkOption {
      description = "The name of the secret on the remote host.";
      default = name;
      type = with lib.types; str;
    };

    hostname = with lib.types; str;

    # TODO Define plans for passing secrets to hosts via SSH
  };

  # Make the options for provisioning a secret
  secretOptions = name: {
    create = mkCommandOptions "create the secret";
    destroy = mkCommandOptions "destroy the secret";
    activate = mkCommandOptions "activate the secret";
    deactivate = mkCommandOptions "deactivate the secret";
    test = mkCommandOptions "test the activated secret";

    derived = lib.mkOption {
      description = "Plans that derive from the secret";
      default = { };
      type =
        with lib.types;
        attrsOf (
          submodule (
            { ... }:
            {
              options = secretOptions;
            }
          )
        );
    };

    systemd = lib.mkOption {
      description = "Systemd services which will use the secret";
      default = { };
      type =
        with lib.types;
        attrsOf (
          submodule (
            { name, ... }:
            {
              options = serviceOptions name;
            }
          )
        );
    };

    remote = lib.mkOption {
      description = "Remote secrets";
      default = { };
      type =
        with lib.types;
        attrsOf (
          submodule (
            { name, ... }:
            {
              options = remoteOptions name;
            }
          )
        );
    };
  };

  # One or more strings
  stringOrStrings =
    with lib.types;
    attrsOf (oneOf [
      str
      (listOf str)
    ]);

  # Options for the secret agent service
  secret-agent = {
    enable = lib.mkEnableOption "secret agent";
    package = lib.mkPackageOption {
      secret-agent = packages.${pkgs.system}.secret-agent;
    } "secret-agent" { };
    roles = lib.mkOption {
      description = "Roles and their permissions";
      type =
        with lib.types;
        attrsOf (submodule {
          options = {
            permissions = lib.mkOption {
              description = "The permissions assigned to a role";
              type = stringOrStrings;
            };
          };
        });
      default.admin.permissions = {
        secrets = "all";
        instances = "all";
      };
    };
    claims = {
      users = lib.mkOption {
        description = "Users and the roles they can assume";
        type = stringOrStrings;
        default.root = "admin";
      };
      groups = lib.mkOption {
        description = "Groups and the roles they can assume";
        type = stringOrStrings;
        default.secret-agent = "admin";
      };
    };
    secrets = lib.mkOption {
      description = "Secrets";
      type =
        with lib.types;
        attrsOf (
          submodule (
            { name, ... }:
            {
              options = secretOptions name;
            }
          )
        );
      default = { };
    };
  };

  cfg = config.services.secret-agent;

  # Map the nix secrets config into a service secrets config
  makeSecretsConfig = lib.attrsets.mapAttrsToList (
    id: secret: {
      inherit id;
      inherit (secret)
        create
        destroy
        activate
        deactivate
        test
        ;
      derived = makeSecretsConfig secret.derived;
    }
  );

  # Write the permissions config file for the service backend
  permissionsFile = pkgs.writeText "permissions.config" (
    builtins.toJSON {
      claims = {
        inherit (cfg.claims) users groups;
      };
      inherit (cfg) roles;
    }
  );

  # Write the secrets config file for the service backend
  secretsFile = pkgs.writeText "secret-agent.config" (
    builtins.toJSON {
      secrets = makeSecretsConfig cfg.secrets;
    }
  );
in
{
  options.services = {
    inherit secret-agent;
  };

  config = lib.mkIf cfg.enable {
    systemd.services =
      (lib.attrsets.concatMapAttrs (
        secret: secretCfg:
        lib.attrsets.concatMapAttrs (service: serviceCfg: {
          "${service}".serviceConfig = lib.mkIf serviceCfg.enable {
            # Mount the decrypted credential on the bind path
            BindPaths = lib.mkIf (serviceCfg.bindPath != null) [
              "%d/${serviceCfg.name}:${serviceCfg.bindPath}${
                if (builtins.match "$.*/^" serviceCfg.bindPath) != null then serviceCfg.name else ""
              }"
            ];
            # Load the encrypted credential
            LoadCredentialEncrypted = [
              "${serviceCfg.name}:/etc/credstore.encrypted/secret-agent/${serviceCfg.name}.cred"
            ];
            # Suppress unencrypted credentials
            LoadCredential = lib.mkIf serviceCfg.suppressUnencrypted (lib.mkForce [ ]);
          };
        }) secretCfg.systemd
      ) cfg.secrets)
      // {
        "secret-agent" = {
          enable = true;
          description = "Secret agent service";
          path = with pkgs; [
            bash
            jq
            coreutils
          ];
          serviceConfig = {
            Type = "simple";
            Restart = "no";
            ExecStart = "${cfg.package}/bin/secret-agent serve -S ${secretsFile} -P ${permissionsFile} -D ./dbfile";
            NonBlocking = true;
          };
          requires = [ "secret-agent.socket" ];
          after = [ "secret-agent.socket" ];
        };
      };

    environment.systemPackages = [
      (cfg.package.overrideAttrs (prevAttrs: {
        nativeBuildInputs = (prevAttrs.nativeBuildInputs or [ ]) ++ [ pkgs.makeBinaryWrapper ];
        postInstall = (prevAttrs.postInstall or "") + ''
          wrapProgram $out/bin/secret-agent \
            --set CLIENT_SOCKET /tmp/secret-agent.socket
        '';
      }))
    ];

    systemd.sockets.secret-agent = {
      enable = true;
      wantedBy = [ "sockets.target" ];
      description = "Socket to communicate with secret agent";
      listenStreams = [ "/tmp/secret-agent.socket" ];
      socketConfig = {
        NoDelay = true;
      };
    };

    users.groups.secret-agent = { };
    users.users.secret-agent = {
      isSystemUser = true;
      description = "Secret Agent";
      group = "secret-agent";
      extraGroups = [ "secret-agent" ];
      packages = [ ];
    };
  };
}
