# Windows Service Deployment

Alighieri can run as a native Windows Service while keeping the SOCKS5 server
runtime shared with interactive console mode.

## Paths

Default deployment layout:

```text
C:\ProgramData\Alighieri\
├── alighieri.conf
├── service-config-path.txt
└── logs\
    └── alighieri.log
```

`service-config-path.txt` records the configuration path used at install time
so `alighieri service start` can validate the same file before starting the
service. It stores only a path, not credentials.

## Commands

Run these from an elevated Administrator shell:

```powershell
alighieri service install --config "C:\ProgramData\Alighieri\alighieri.conf"
alighieri service start
alighieri service status
alighieri service reload
alighieri service stop
alighieri service uninstall
```

Interactive mode remains available:

```powershell
alighieri --config "C:\ProgramData\Alighieri\alighieri.conf"
```

## Service Identity

The installed service uses:

- service name: `Alighieri`
- display name: `Alighieri SOCKS5 Proxy Server`
- startup type: automatic
- account: `NT AUTHORITY\LocalService`
- Event Log source: `Alighieri` in the Windows Application log

`LocalService` is the default because the proxy does not need broad local
machine privileges. Use tighter file ACLs on `alighieri.conf` and the userlist
file so only administrators and the service account can read them.

## Logging

Service mode writes logs to:

```text
C:\ProgramData\Alighieri\logs\alighieri.log
```

Service install registers the `Alighieri` Event Log source. Service mode writes
startup, stop, reload-request, and startup/runtime failure events to the Windows
Application log. File logging remains the detailed operational log.

Expected Event IDs:

| Event ID | Meaning |
| --- | --- |
| `100` | Service installed |
| `101` | Service started |
| `102` | Service stopped |
| `103` | Reload requested |
| `200` | Configuration load failure |
| `201` | Service file logging failure |
| `202` | Tokio runtime build failure |
| `203` | Server bind failure |
| `204` | Server runtime failure |

## Reload Behavior

`alighieri service reload` validates the installed configuration path and then
sends a user-defined Service Control Manager control code to the running
service. New client connections use the reloaded ACLs, DNS policy,
authentication settings, userlist, timeout values, and rate-limit settings.
Existing connections continue with the configuration they accepted under.

Listener addresses, `maxconnections`, metrics listener settings, TLS listener
settings, and logging sinks remain process-level resources and require a
service restart.

## Stop Behavior

When the Service Control Manager sends a stop request, Alighieri signals the
same async server runtime used in console mode. The listener is dropped and the
process exits after the runtime observes the shutdown signal. The service
advertises both `STOP` and `SHUTDOWN`, so an operating-system shutdown or restart
runs the same graceful stop (final log flush, clean `Stopped` status) rather than
terminating the process abruptly.

## Crash Recovery

The installer configures Service Control Manager recovery actions so the service
restarts automatically if the process crashes — 5 seconds after the first
failure, then 30, then 60, with the failure count reset after an hour of
stability. This is the Windows equivalent of the systemd unit's
`Restart=on-failure`. A clean exit with a configuration-error code is **not**
restarted (a restart would not fix a broken config); fix the configuration and
start the service again.

## Smoke Test

Manual Windows Service smoke testing requires an elevated Administrator
PowerShell because it writes the Service Control Manager database and the HKLM
Event Log source registry path. From a Windows host with `alighieri.exe`
available on `PATH`, run:

```powershell
.\doc\windows-service-smoke-test.ps1 `
  -Alighieri alighieri `
  -Config "C:\ProgramData\Alighieri\alighieri.conf"
```

The script validates the configuration, installs the service, starts it,
requests a reload, prints recent `Alighieri` Application log entries, stops the
service, and uninstalls it. Use `-SkipCleanup` to leave the service installed
for manual inspection.
