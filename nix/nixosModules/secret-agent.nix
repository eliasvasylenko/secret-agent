{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.secret-agent;

  mkCommand =
    purpose:
    mkOption {
      description = "Command to ${purpose}.";
      type = with types; nullOr str;
      default = null;
    };

  serviceOptions = name: {
    enable = mkEnableOption "service credential";

    transform = mkOption {
      description = "Command to transform the generated secret.";
      default = null;
      type = with types; nullOr str;
    };

    suppressUnencrypted = mkOption {
      description = ''
        Suppress existing unencrypted LoadCredential options.
        This is sometimes needed in case of collision.
      '';
      default = false;
      type = with types; bool;
    };

    name = mkOption {
      description = "The name of the credential when encrypted with systemd-creds.";
      default = name;
      type = with types; str;
    };

    bindPath = mkOption {
      description = ''
        Path to mount the credential file privately to the service.
        This is sometimes needed if the secret path is configured in a
        context where we can't expand env vars or systemd specifiers.
      '';
      default = null;
      type = with types; nullOr str;
    };
  };

  remoteOptions = name: {
    enable = mkEnableOption "remote secret";

    transform = mkOption {
      description = "Command to transform the generated secret.";
      default = null;
      type = with types; nullOr str;
    };

    name = mkOption {
      description = "The name of the secret on the remote hosta.";
      default = name;
      type = with types; str;
    };

    # TODO Define plans for passing secrets to hosts via SSH
  };

  secretOptions = name: {
    create = mkCommand "create the secret";
    destroy = mkCommand "destroy the secret";
    activate = mkCommand "activate the secret";
    deactivate = mkCommand "deactivate the secret";
    test = mkCommand "test the activated secret";

    plans = mkOption {
      description = "Plans that derive from the secret";
      default = { };
      type = types.attrsOf (
        types.submodule (
          { ... }:
          {
            options = secretOptions;
          }
        )
      );
    };

    systemd = mkOption {
      description = "Systemd services which will use the secret.";
      default = { };
      type = types.attrsOf (
        types.submodule (
          { name, ... }:
          {
            options = serviceOptions name;
          }
        )
      );
    };

    remote = mkOption {
      description = "Remote secrets .";
      default = { };
      type = types.attrsOf (
        types.submodule (
          { name, ... }:
          {
            options = remoteOptions name;
          }
        )
      );
    };
  };
in
{
  options = {
    services.secret-agent = {
      enable = mkEnableOption "secret agent";
      package = mkPackageOption { secret-agent = pkgs.secret-agent; } "secret-agent" { };
    };
    secret-agent = mkOption {
      description = "Secret secrets.";
      type = types.attrsOf (
        types.submodule (
          { name, ... }:
          {
            options = secretOptions name;
          }
        )
      );
      default = { };
    };
  };

  config =
    let
      configFile = pkgs.writeText "secret-agent-config.json" (builtins.toJSON cfg);
    in
    {
      systemd.services =
        (attrsets.concatMapAttrs (
          secret: secretCfg:
          attrsets.concatMapAttrs (service: serviceCfg: {
            "${service}".serviceConfig = mkIf serviceCfg.enable {
              # Mount the decrypted credential on the bind path
              BindPaths = mkIf (serviceCfg.bindPath != null) [
                "%d/${serviceCfg.name}:${serviceCfg.bindPath}${
                  if (builtins.match "$.*/^" serviceCfg.bindPath) != null then serviceCfg.name else ""
                }"
              ];
              # Load the encrypted credential
              LoadCredentialEncrypted = [
                "${serviceCfg.name}:/etc/credstore.encrypted/secret-agent/${serviceCfg.name}.cred"
              ];
              # Suppress unencrypted credentials
              LoadCredential = mkIf (serviceCfg.suppressUnencrypted) (mkForce [ ]);
            };
          }) secretCfg.systemd
        ) cfg)
        // {
          "secret-agent@" = {
            enable = true;
            description = "Secret agent service";
            path = with pkgs; [
              bash
              jq
              coreutils
            ];
            environment = {
              SECRET_AGENT_CONFIG = configFile;
            };
            serviceConfig = {
              Type = "simple";
              Restart = "no";
              ExecStart = "${cfg.services.secret-agent.package}/bin/secret-agent serve -s ${configFile} -D ${dbFile} -S /tmp/secret-agent.socket";
              NonBlocking = true;
            };
            requires = [ "secret-agent.socket" ];
            after = [ "secret-agent.socket" ];
          };
        };

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
        openssh.authorizedKeys.keys = [
          "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJbrxnO/GFEaCt8hdFr/ShLWHkG7rEQOcKapRIBZPt70FnbZKcQXgrgQt3fMBI6bSq1oa8hZHx8iUESgLkwXO83YJ/Y1GC+wDvVT/lluUx+Imm/mCn/DNqrcSW5IHHrI6Q=="
        ];
      };
    };
}
