# NixOS integration: cage secrets → systemd credentials (see `cage skill infra`).
#
# For every configured consumer unit <name>:
#   cage-credentials-<name>.service  oneshot preparer (root): decrypts the
#     sources with cage.identityFile and atomically publishes the
#     complete set into <stagingDir>/<name>.service on a root-only ramfs;
#   <name>.service  Requires/After the preparer, loads every file with
#     LoadCredential=, removes the staging copy right after start and after
#     stop. The preparer runs on every start (including automatic restarts),
#     so a start never uses an older generation than the sources on disk.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkOption
    mkEnableOption
    mkIf
    mkDefault
    mkBefore
    types
    ;

  # Top-level `cage`: `services.cage` is the Wayland kiosk compositor in nixpkgs.
  cfg = config.cage;
  exe = lib.getExe' cfg.package "cage";
  storeDir = builtins.storeDir;

  inStore = p: lib.hasPrefix "${storeDir}/" p;

  sourcePath = src: if builtins.isPath src.path then "${src.path}" else src.path;

  sourceType = types.coercedTo (types.either types.path types.str) (path: { inherit path; }) (
    types.submodule {
      options = {
        path = mkOption {
          type = types.either types.path types.str;
          description = ''
            Encrypted cage file (`*.cage`: a secret or a compiled env bundle).
            A Nix path is copied into the store (ciphertext only); a string
            is an absolute runtime path read at every start.
          '';
        };
        prefix = mkOption {
          type = types.nullOr (types.strMatching "[A-Za-z_][A-Za-z0-9_]*");
          default = null;
          description = "Prefix for the variables of this .env source.";
        };
      };
    }
  );

  credentialType = types.submodule {
    options.sources = mkOption {
      type = types.nonEmptyListOf sourceType;
      description = ''
        Sources of one credential: a single blob, or .env secrets/env bundles
        merged into one dotenv file (colliding variable names are an error).
      '';
    };
  };

  consumerType = types.submodule {
    options = {
      credentials = mkOption {
        type = types.attrsOf credentialType;
        default = { };
        description = ''
          Credentials by name; the unit reads `$CREDENTIALS_DIRECTORY/<name>`
          (`%d/<name>` in unit settings).
        '';
      };
      memoryProtection = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Forbid swap (MemorySwapMax=0) and core dumps (LimitCORE=0) for the
          consumer: it holds the decrypted values in memory.
        '';
      };
    };
  };

  unitName = name: "${name}.service";
  preparerName = name: "cage-credentials-${name}";

  manifest =
    name: consumer:
    pkgs.writeText "cage-credentials-${name}.json" (
      builtins.toJSON {
        version = 1;
        unit = unitName name;
        identity = cfg.identityFile;
        stagingDir = cfg.stagingDir;
        credentials = lib.mapAttrsToList (credName: cred: {
          name = credName;
          sources = map (
            src:
            {
              path = sourcePath src;
            }
            // lib.optionalAttrs (src.prefix != null) { inherit (src) prefix; }
          ) cred.sources;
        }) consumer.credentials;
      }
    );

  noSwapNoCore = {
    MemorySwapMax = 0;
    LimitCORE = 0;
  };

  preparerUnit = name: consumer: {
    description = "Prepare cage credentials for ${unitName name}";
    before = [ (unitName name) ];
    unitConfig.RequiresMountsFor = [ cfg.stagingDir ];
    # Runs on every start of the consumer; the consumer's own start limit
    # governs restart rate.
    startLimitIntervalSec = 0;
    serviceConfig = noSwapNoCore // {
      Type = "oneshot";
      ExecStart = "${exe} credentials prepare ${manifest name consumer}";
      User = "root";
      UMask = "0077";
      # Reads the identity and runtime sources; writes only the staging dir.
      CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" ];
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = "read-only";
      ReadWritePaths = [ cfg.stagingDir ];
      PrivateTmp = true;
      PrivateDevices = true;
      PrivateNetwork = true;
      RestrictAddressFamilies = [ "AF_UNIX" ];
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      ProtectHostname = true;
      ProtectProc = "invisible";
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      SystemCallArchitectures = "native";
      SystemCallFilter = [
        "@system-service"
        "~@privileged @resources"
      ];
      KeyringMode = "private";
    };
  };

  consumerUnit = name: consumer: {
    requires = [ "${preparerName name}.service" ];
    after = [ "${preparerName name}.service" ];
    serviceConfig = {
      LoadCredential = lib.mapAttrsToList (
        credName: _: "${credName}:${cfg.stagingDir}/${unitName name}/${credName}"
      ) consumer.credentials;
      # Credentials are copied by systemd before the first process starts;
      # the staging copy is not needed afterwards. "+" runs with full
      # privileges regardless of the unit's User=.
      ExecStartPost = mkBefore [ "+${exe} credentials clean ${manifest name consumer}" ];
      ExecStopPost = [ "+${exe} credentials clean ${manifest name consumer}" ];
    }
    // lib.optionalAttrs consumer.memoryProtection (lib.mapAttrs (_: mkDefault) noSwapNoCore);
  };
in
{
  options.cage = {
    enable = mkEnableOption "delivery of cage secrets to systemd services as credentials";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "cage.packages.\${system}.default";
      description = "cage package.";
    };

    identityFile = mkOption {
      type = types.str;
      example = "/etc/ssh/ssh_host_ed25519_key";
      description = ''
        Runtime path of the machine's SSH private key (unencrypted, mode 0600)
        used to decrypt. A string, not a Nix path: the key must never be
        copied into the Nix store. No other key is ever tried.
      '';
    };

    stagingDir = mkOption {
      type = types.str;
      default = "/run/cage-credentials";
      description = ''
        Root-only ramfs mount (created by this module) where preparers publish
        plaintext until systemd loads it. ramfs is never swapped.
      '';
    };

    services = mkOption {
      type = types.attrsOf consumerType;
      default = { };
      example = lib.literalExpression ''
        {
          myapp.credentials = {
            config.sources = [ ./secrets/myapp.cage { path = "/var/lib/myapp/extra.cage"; prefix = "EXTRA_"; } ];
            "tls.key".sources = [ ./secrets/myapp-tls-key.cage ];
          };
        }
      '';
      description = ''
        Consumer systemd services (attribute name = systemd.services name)
        and their credentials. The service definition itself (ExecStart,
        User, …) stays in systemd.services.<name>.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.hasPrefix "/" cfg.identityFile && !inStore cfg.identityFile;
        message = "cage.identityFile must be an absolute runtime path outside the Nix store.";
      }
      {
        assertion =
          lib.hasPrefix "/" cfg.stagingDir && cfg.stagingDir != "/" && !inStore cfg.stagingDir;
        message = "cage.stagingDir must be an absolute path outside the Nix store.";
      }
    ]
    ++ lib.concatLists (
      lib.mapAttrsToList (
        name: consumer:
        let
          svc = config.systemd.services.${name};
        in
        [
          {
            assertion = consumer.credentials != { };
            message = "cage.services.${name}: no credentials configured.";
          }
          {
            assertion = (svc.serviceConfig ? ExecStart) || svc.script != "";
            message = "cage.services.${name}: systemd.services.${name} is not defined (no ExecStart/script).";
          }
          {
            assertion = lib.all (n: builtins.match "[A-Za-z0-9_][A-Za-z0-9_.-]*" n != null) (
              lib.attrNames consumer.credentials
            );
            message = "cage.services.${name}: credential names must match [A-Za-z0-9_][A-Za-z0-9_.-]*.";
          }
        ]
        ++ lib.concatLists (
          lib.mapAttrsToList (
            credName: cred:
            map (src: {
              assertion =
                let
                  p = sourcePath src;
                in
                lib.hasPrefix "/" p && lib.hasSuffix ".cage" p;
              message = "cage.services.${name}.credentials.${credName}: sources must be absolute *.cage paths.";
            }) cred.sources
          ) consumer.credentials
        )
      ) cfg.services
    );

    warnings = lib.concatLists (
      lib.mapAttrsToList (
        name: _:
        let
          sc = config.systemd.services.${name}.serviceConfig;
        in
        lib.optional (!(sc ? User) && !(sc.DynamicUser or false))
          "cage.services.${name}: the unit runs as root; run it as a dedicated unprivileged user."
      ) cfg.services
    );

    systemd.mounts = [
      {
        description = "cage credentials staging (ramfs, non-swappable)";
        what = "ramfs";
        where = cfg.stagingDir;
        type = "ramfs";
        options = "mode=0700,nosuid,nodev,noexec";
      }
    ];

    systemd.services = lib.mkMerge [
      (lib.mapAttrs' (name: consumer: lib.nameValuePair (preparerName name) (preparerUnit name consumer)) cfg.services)
      (lib.mapAttrs consumerUnit cfg.services)
    ];
  };
}
