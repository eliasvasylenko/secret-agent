{ packages, ... }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  # Command can be either a string (simple) or an object with script and optional credential
  commandType =
    with lib.types;
    either str (submodule {
      options = {
        script = lib.mkOption {
          description = "Command script to execute";
          type = str;
        };
        environment = lib.mkOption {
          description = "Environment variables to set for the command";
          type = nullOr (attrsOf str);
          default = null;
        };
        credential = lib.mkOption {
          description = "Credential to use for the command";
          type = nullOr (submodule {
            options = {
              uid = lib.mkOption {
                description = "User ID";
                type = nullOr int;
                default = null;
              };
              gid = lib.mkOption {
                description = "Group ID";
                type = nullOr int;
                default = null;
              };
              groups = lib.mkOption {
                description = "Supplementary group IDs";
                type = nullOr (listOf int);
                default = null;
              };
            };
          });
          default = null;
        };
      };
    });

  # Make the options for a secret command
  mkCommandOptions =
    purpose:
    lib.mkOption {
      description = "Command to ${purpose}.";
      type = with lib.types; nullOr commandType;
      default = null;
    };

  # Make the options for provisioning a secret
  secretOptions = name: {
    environment = lib.mkOption {
      description = "The environment variables to surface to the secret commands";
      default = { };
      type = with lib.types; attrsOf str;
    };
    create = mkCommandOptions "create the secret";
    destroy = mkCommandOptions "destroy the secret";
    activate = mkCommandOptions "activate the secret";
    deactivate = mkCommandOptions "deactivate the secret";
    test = mkCommandOptions "test the activated secret";

    derive = lib.mkOption {
      description = "Plans that derive from the secret";
      default = { };
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
    package = lib.mkPackageOption packages.${pkgs.system} "secret-agent" {
      default = "default";
    };
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
        all = "any";
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

  # Convert a command (string or object) to JSON format
  makeCommandConfig =
    command:
    if command == null then
      null
    else if builtins.isString command then
      command
    else
      {
        script = command.script;
      }
      // lib.optionalAttrs (command ? credential && command.credential != null) {
        credential = lib.filterAttrs (n: v: v != null) command.credential;
      };

  # Map the nix secrets config into a service secrets config
  makeSecretsConfig =
    secrets:
    lib.lists.sortOn ({ name, ... }: name) (
      lib.attrsets.mapAttrsToList (
        name: secret:
        lib.attrsets.filterAttrs (n: v: v != null) {
          inherit name;
          environment = secret.environment;
          create = makeCommandConfig secret.create;
          destroy = makeCommandConfig secret.destroy;
          activate = makeCommandConfig secret.activate;
          deactivate = makeCommandConfig secret.deactivate;
          test = makeCommandConfig secret.test;
          derive = makeSecretsConfig secret.derive;
        }
      ) secrets
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
    systemd.services.secret-agent = {
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
