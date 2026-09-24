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
    version = lib.mkOption {
      description = ''
        Version of this secret's plan. Instances record this at create time; later
        destroy/activate/deactivate/test use the latest stored plan for that version. Bump when
        provisioning semantics change incompatibly; leave unchanged to allow script fixes
        (e.g. a broken destroy) to apply to existing instances.
      '';
      type = lib.types.ints.positive;
      default = 1;
    };
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
  };

  # One or more strings
  stringOrStrings =
    with lib.types;
    attrsOf (oneOf [
      str
      (listOf str)
    ]);

  sshKeysType = lib.types.submodule {
    options = {
      keys = lib.mkOption {
        description = "SSH public key lines.";
        type = lib.types.listOf lib.types.str;
        default = [ ];
      };
      keyFiles = lib.mkOption {
        description = "Files containing SSH public key lines.";
        type = lib.types.listOf lib.types.path;
        default = [ ];
      };
    };
  };

  # Options for the secret agent service
  secret-agent = {
    enable = lib.mkEnableOption "secret agent";
    package = lib.mkPackageOption packages.${pkgs.stdenv.hostPlatform.system} "secret-agent" {
      default = "default";
    };
    roles = lib.mkOption {
      description = "Roles and their permissions";
      type =
        with lib.types;
        attrsOf (submodule {
          options = {
            permissions = lib.mkOption {
              description = "Actions granted on every secret. Subjects are all, secrets, and instances.";
              type = stringOrStrings;
              default = { };
            };
            secrets = lib.mkOption {
              description = ''
                Permissions for named secrets. Each value has the same shape as
                `permissions` and applies only to that secret.
                Global permissions still apply to every secret.
              '';
              type = lib.types.attrsOf stringOrStrings;
              default = { };
              example.secret-a.all = "any";
            };
          };
        });
      default.admin.permissions = {
        all = "any";
      };
    };
    bindings = {
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
      forwardAuth = {
        peers = lib.mkOption {
          description = ''
            Unix peers allowed to assert the end-user via HTTP header (typically
            the reverse-proxy user, e.g. `caddy`). The header is ignored unless
            `SO_PEERCRED` matches one of these names or uids.
          '';
          type = lib.types.listOf lib.types.str;
          default = [ ];
          example = [ "caddy" ];
        };
        header = lib.mkOption {
          description = ''
            Header a trusted hop uses to name the end user. Empty (default)
            uses the agent's default; only set this to pass `-H` on
            dial-stdio and override ForwardAuth.Header.
          '';
          type = lib.types.str;
          default = "";
        };
      };
    };
    ssh = {
      enable = lib.mkEnableOption ''
        unix user `secret-agent` on host `services.openssh` (`Match User` only).
        sshd reads Nix-pinned keys (`ssh.shared`) and fragments in
        /var/lib/secret-agent/ssh/authorized_keys.d (activate). Requires
        services.openssh.enable
      '';
      shared = lib.mkOption {
        description = ''
          Optional Nix-pinned keys for the shared account. Requires
          ssh.enable. Attr names are wrapped with `restrict,command=` /
          `dial-stdio -u`. Rebuild owns only these pins; agent fragments
          are a separate sshd source and are not clobbered.
        '';
        type = lib.types.attrsOf sshKeysType;
        default = { };
        example = {
          alice.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
          ];
        };
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

  sshHasStaticKeys = lib.any (spec: spec.keys != [ ] || spec.keyFiles != [ ]) (
    lib.attrValues cfg.ssh.shared
  );
  sshAgentKeysDir = "/var/lib/secret-agent/ssh/authorized_keys.d";
  forwardAuthPeers = lib.unique (
    cfg.bindings.forwardAuth.peers ++ lib.optionals cfg.ssh.enable [ "secret-agent" ]
  );

  dialStdio = "${cfg.package}/bin/secret-agent dial-stdio";
  dialStdioHeader = lib.optionalString (
    cfg.bindings.forwardAuth.header != ""
  ) " -H ${cfg.bindings.forwardAuth.header}";

  wrapSharedKey =
    name: key:
    let
      k = lib.removeSuffix "\n" (lib.removeSuffix "\r" key);
    in
    lib.optionalString (
      k != ""
    ) "restrict,command=\"${dialStdio} -u ${name}${dialStdioHeader}\" ${k}\n";

  sharedAuthorizedKeys = pkgs.writeText "secret-agent-authorized-keys" (
    lib.concatStrings (
      lib.mapAttrsToList (
        name: spec:
        lib.concatMapStrings (wrapSharedKey name) (spec.keys ++ map builtins.readFile spec.keyFiles)
      ) cfg.ssh.shared
    )
  );

  authorizedKeysCommand = pkgs.writeShellScript "secret-agent-authorized-keys" ''
    for f in ${sshAgentKeysDir}/*; do
      [ -f "$f" ] || continue
      ${pkgs.coreutils}/bin/cat "$f"
    done
  '';

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
      // lib.optionalAttrs (command ? environment && command.environment != null) {
        environment = command.environment;
      }
      // lib.optionalAttrs (command ? credential && command.credential != null) {
        credential = lib.filterAttrs (n: v: v != null) command.credential;
      };

  # Map the nix secrets config into a service secrets config
  makeSecretsConfig =
    secrets:
    lib.lists.sortOn (s: s.id) (
      lib.attrsets.mapAttrsToList (
        name: secret:
        lib.attrsets.filterAttrs (n: v: v != null) {
          id = name;
          version = secret.version;
          environment = secret.environment;
          create = makeCommandConfig secret.create;
          destroy = makeCommandConfig secret.destroy;
          activate = makeCommandConfig secret.activate;
          deactivate = makeCommandConfig secret.deactivate;
          test = makeCommandConfig secret.test;
        }
      ) secrets
    );

  # Write the permissions config file for the service backend
  permissionsFile = pkgs.writeText "permissions.config" (
    builtins.toJSON {
      bindings = {
        inherit (cfg.bindings) users groups;
      }
      // lib.optionalAttrs (forwardAuthPeers != [ ]) {
        forwardAuth = {
          peers = forwardAuthPeers;
        }
        // lib.optionalAttrs (cfg.bindings.forwardAuth.header != "") {
          header = cfg.bindings.forwardAuth.header;
        };
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
    assertions = [
      {
        assertion = !cfg.ssh.enable || config.services.openssh.enable;
        message = "services.secret-agent.ssh.enable requires services.openssh.enable.";
      }
    ];

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
            --set CLIENT_ADDRESS /tmp/secret-agent.socket
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
    users.users.secret-agent = lib.mkIf cfg.ssh.enable {
      isSystemUser = true;
      description = "Secret Agent";
      group = "secret-agent";
      shell = pkgs.bash;
      openssh.authorizedKeys.keyFiles = lib.mkIf sshHasStaticKeys [ sharedAuthorizedKeys ];
    };

    system.activationScripts.secret-agent-ssh = lib.mkIf cfg.ssh.enable ''
      install -d -m 755 /var/lib/secret-agent/ssh/authorized_keys.d
      install -m 755 ${authorizedKeysCommand} /var/lib/secret-agent/ssh/authorized-keys-command
    '';

    # Nix pins: AuthorizedKeysFile (openssh.authorizedKeys).
    # Activate fragments: AuthorizedKeysCommand. Rebuild does not touch the dir.
    services.openssh.extraConfig = lib.mkIf cfg.ssh.enable (
      lib.mkAfter ''
        Match User secret-agent
          PasswordAuthentication no
          KbdInteractiveAuthentication no
          PubkeyAuthentication yes
          AuthenticationMethods publickey
          PermitTTY no
          AllowTcpForwarding no
          AllowStreamLocalForwarding no
          X11Forwarding no
          AllowAgentForwarding no
          PermitTunnel no
          GatewayPorts no
          AuthorizedKeysCommand /var/lib/secret-agent/ssh/authorized-keys-command
          AuthorizedKeysCommandUser nobody
      ''
    );
  };
}
