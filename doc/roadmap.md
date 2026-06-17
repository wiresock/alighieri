# Alighieri Roadmap

## Milestone 1: Core TCP Proxy

- Implement SOCKS5 greeting and request parsing.
- Implement TCP CONNECT relay.
- Add basic configuration loading.
- Add deny-by-default client and SOCKS ACLs.

## Milestone 2: Authentication and ACLs

- Add username/password authentication.
- Add CIDR, port, command, protocol, and method selectors.
- Add configuration validation and useful operator errors.

## Milestone 3: UDP Proxy

- Implement UDP ASSOCIATE.
- Reuse SOCKS ACLs for UDP destinations.
- Drop fragmented or malformed UDP datagrams.
- Add UDP relay integration coverage.

## Milestone 4: Windows Service Support

- Add Windows Service lifecycle integration.
- Add service install, uninstall, start, stop, and status commands.
- Add Windows-specific configuration and logging paths.
- Reuse graceful shutdown handling for Service Control Manager stop requests.
- Document service installation and deployment.

## Milestone 5: Documentation and Hardening

- Add Windows deployment examples.
- Write and maintain README coverage for common deployment modes.
- Improve error messages.
- Add limits and timeouts.
- Run `cargo fmt`, `cargo clippy`, and `cargo test`.
