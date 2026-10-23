# VM test of nixosModules.cage with synthetic secrets: delivery, isolation,
# automatic restart, rotation of a runtime source, failure without stale or
# partial credentials, and absence of values in env/argv/journal/units.
{ self, pkgs }:
let
  cage = self.packages.${pkgs.stdenv.hostPlatform.system}.default;

  fixtures = pkgs.runCommand "cage-test-fixtures" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    bash ${./fixtures.sh} ${cage}/bin/cage $out
  '';

  app = pkgs.writeShellScript "cage-test-app" ''
    set -eu
    test -s "$CREDENTIALS_DIRECTORY/config"
    test -s "$CREDENTIALS_DIRECTORY/tls.key"
    exec ${pkgs.coreutils}/bin/sleep infinity
  '';
in
pkgs.testers.runNixOSTest {
  name = "cage-credentials";

  nodes.machine = {
    imports = [ self.nixosModules.cage ];

    environment.etc."cage-test/machine" = {
      source = "${fixtures}/machine";
      mode = "0600";
    };
    systemd.tmpfiles.rules = [ "d /var/lib/cage-runtime 0700 root root -" ];

    users.users.app = {
      isSystemUser = true;
      group = "app";
    };
    users.groups.app = { };

    cage = {
      enable = true;
      identityFile = "/etc/cage-test/machine";
      services.app.credentials = {
        config.sources = [
          {
            path = "/var/lib/cage-runtime/db.cage";
            prefix = "DB_";
          }
          "${fixtures}/api.cage"
        ];
        "tls.key".sources = [ "${fixtures}/tls-key.cage" ];
      };
    };

    systemd.services.app.serviceConfig = {
      User = "app";
      Group = "app";
      ExecStart = "${app}";
      Restart = "always";
      RestartSec = "1s";
    };
  };

  testScript = ''
    def main_pid():
        return machine.succeed("systemctl show -P MainPID app.service").strip()

    def staging_empty():
        machine.succeed('test -z "$(ls -A /run/cage-credentials)"')

    def runtime_source(name):
        machine.succeed(f"install -m600 ${fixtures}/{name} /var/lib/cage-runtime/db.cage")

    machine.wait_for_unit("multi-user.target")

    with subtest("delivery"):
        runtime_source("db-v1.cage")
        machine.succeed("systemctl start app.service")
        machine.wait_for_unit("app.service")
        config = machine.succeed("cat /run/credentials/app.service/config")
        assert "DB_PASSWORD=SYNTHETIC-db-v1" in config, config
        assert "DB_USER=app" in config and "TOKEN=SYNTHETIC-api" in config, config
        assert "SYNTHETIC-blob" in machine.succeed("cat /run/credentials/app.service/tls.key")

    with subtest("staging: ramfs, root-only, emptied after start"):
        machine.succeed("findmnt -n -o FSTYPE /run/cage-credentials | grep -qx ramfs")
        assert machine.succeed("stat -c %a:%U /run/cage-credentials").strip() == "700:root"
        staging_empty()

    with subtest("isolation and memory protection"):
        pid = main_pid()
        machine.fail(f"grep -a SYNTHETIC /proc/{pid}/environ /proc/{pid}/cmdline")
        machine.fail("runuser -u app -- cat /etc/cage-test/machine")
        machine.fail("runuser -u app -- ls /run/cage-credentials")
        for unit in ["app.service", "cage-credentials-app.service"]:
            assert machine.succeed(f"systemctl show -P MemorySwapMax {unit}").strip() == "0"
            assert machine.succeed(f"systemctl show -P LimitCORE {unit}").strip() == "0"

    with subtest("automatic restart prepares credentials again"):
        pid = main_pid()
        machine.succeed(f"kill -9 {pid}")
        machine.wait_until_succeeds(
            f'p=$(systemctl show -P MainPID app.service); test "$p" != 0 && test "$p" != {pid}'
        )
        machine.wait_for_unit("app.service")
        machine.succeed("grep -q DB_PASSWORD=SYNTHETIC-db-v1 /run/credentials/app.service/config")
        staging_empty()

    with subtest("rotation of a runtime source"):
        runtime_source("db-v2.cage")
        machine.succeed("systemctl restart app.service")
        machine.wait_for_unit("app.service")
        machine.succeed("grep -q DB_PASSWORD=SYNTHETIC-db-v2 /run/credentials/app.service/config")

    for name in ["corrupt.cage", "foreign.cage"]:
        with subtest(f"failure without stale credentials: {name}"):
            runtime_source(name)
            machine.fail("systemctl restart app.service")
            machine.succeed("systemctl is-failed cage-credentials-app.service")
            machine.fail("systemctl is-active app.service")
            machine.fail("test -e /run/credentials/app.service")
            staging_empty()

    with subtest("recovery"):
        runtime_source("db-v1.cage")
        machine.succeed("systemctl start app.service")
        machine.wait_for_unit("app.service")
        machine.succeed("systemctl stop app.service")
        staging_empty()

    with subtest("no values in journal and generated units"):
        machine.fail("journalctl -b --no-pager | grep -a SYNTHETIC")
        machine.fail("grep -Ra SYNTHETIC /etc/systemd/system")
  '';
}
