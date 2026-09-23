# secret-agent

A small agent that orchestrates and audits the lifecycle of *secrets*. You define secret *plans*, consisting of scripts to create, destroy, activate, deactivate, and test instances of a secret. The agent is instructed to follow these plans, tracking which instances and created, active, and tested, and recording who did what and why.

## Why it exists

Many secrets are inherently stateful. We want to say declaratively that “this machine should have credential X, wired into services Y and Z” but for the *current* value and *when* it is rotated live outside the declarative model. Tools like sops-nix and agenix keep sensitive data out of the Nix store by encrypting them and decrypting at activation, but lifecycle stays tied to `nixos-rebuild`.

Instead secret-agent declares only the secret **plans** (i.e. the scripts that do the real work) in your Nix config, while **instance** state (which instances exist, which is active, full history) lives in secret-agent’s SQLite store. So you can:

- **Rotate secrets** without rebuilding or redeploying Nix.
- **Roll back Nix** without affecting which secret instance is active or re-running provisioning.
- **Configure secrets declaratively**, and define dependencies between secrets and services as part of your system configuration.
- **Store secrets however you like:** the agent never holds or generates secret values—it only runs your scripts and records what happened. So you can use the TPM, a secret manager, encrypted files, or anything else.

## Who it's for

Homelabbers using NixOS. People who are willing to take a risk on something immature if it's interesting.

## Architecture docs

- [design.md](docs/design.md) — current design
- [http-api.md](docs/http-api.md) — HTTP routes and JSON
- [plan-federation.md](docs/plan-federation.md) — federation still to build

## How it works

The secret-agent NixOS module will: 

- Generate secret & permission configs from your options and writes them into the Nix store.
- Run secret-agent as a systemd service that listens on a Unix socket.
- Exposes the CLI in your environment, set up to talk to the service socket, so you run `secret-agent` commands to interact with the service.

The secret-agent service will:

- Perform the configured operations to create, destroy, activate, deactivate, and test *instances* of secrets, according to the configured plans.
- Record all operations performed.
- Accept or deny commands according to the configured permissions for the calling user or group.

## Quick start (NixOS)

1. **Add the flake and enable the module** in your NixOS config:

   ```nix
   services.secret-agent.enable = true;
   services.secret-agent.secrets.my-secret = {
     create = "openssl rand -base64 32";
   };
   ```

1. **Set up roles and permissions**:

   By default the `root` user and `secret-agent` group have the `admin` role with all permissions.

   Users and groups are mapped to roles via `services.secret-agent.bindings`, and roles are mapped to permission sets via `services.secret-agent.roles`.

1. **Rebuild and switch** and the CLI will be available on the system (with `CLIENT_ADDRESS` set to the service socket).

1. **Provision and activate an instance**:

   ```bash
   secret-agent create my-secret -r "initial provisioning"
   secret-agent activate my-secret <instance-id> -r "going live"
   ```
