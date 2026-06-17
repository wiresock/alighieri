# SOCKS5 Proxy Concerns Plan

This document tracks implementation concerns found during the SOCKS5 proxy
review. The items are ordered by expected security and operational impact.

> **Status: all five concerns below are implemented.** This document is kept
> for historical context. The handshake/request timeout, UDP endpoint locking,
> dual-stack address selectors, reserved-byte rejection, and the expanded
> authentication / UDP / malformed-frame coverage all landed on `main` and are
> exercised by the module unit tests and `tests/socks5_connect.rs`.

## 1. Add Deadlines for Pre-Relay Client Reads

### Concern

Accepted client connections hold a `maxconnections` semaphore permit while the
server waits for the SOCKS greeting, optional username/password authentication,
and request frame. Those reads currently have no deadline.

A peer can open many TCP connections and then send nothing, or trickle bytes
slowly, consuming all connection slots before authentication or authorization.

### Proposed Fix

- Add a configurable handshake/request timeout.
- Apply it around:
  - the SOCKS5 greeting read,
  - username/password sub-negotiation,
  - the initial SOCKS request read.
- Close the connection when the timeout expires.
- Keep this timeout separate from `iotimeout`, which applies after a relay is
  established.

### Validation

- Add tests for a client that connects and sends no greeting.
- Add tests for a partial greeting/request that never completes.
- Confirm the semaphore slot is released after timeout.
- Confirm normal CONNECT and UDP ASSOCIATE flows still pass.

## 2. Bind UDP Associations to a Client Endpoint

### Concern

The UDP relay accepts datagrams from any source port as long as the source IP
matches the TCP client IP. It then updates the remembered client UDP address to
the most recent sender.

On shared hosts or behind NAT, another process using the same public/source IP
could inject packets into an authenticated association or redirect replies to
its own UDP port.

### Proposed Fix

- Lock each UDP association to one client UDP `SocketAddr`.
- Prefer the endpoint requested by the UDP ASSOCIATE command when it is usable.
- If the request uses `0.0.0.0:0`, lock to the first valid UDP datagram source
  after parsing and authorization.
- Drop later datagrams from different ports, even when the IP matches.

### Validation

- Add an end-to-end UDP relay test with a real UDP echo target.
- Add a test showing a second UDP socket from the same IP cannot take over the
  association.
- Confirm fragmented UDP datagrams are still dropped.

## 3. Make Omitted Address Selectors Truly Match IPv4 and IPv6

### Concern

The documentation says omitted selectors match anything, but the parser fills
omitted `from` and `to` selectors with `0.0.0.0/0`. The CIDR matcher correctly
keeps IPv4 and IPv6 separate, so this default does not match IPv6 clients or
destinations.

This is surprising because the SOCKS5 parser supports IPv6 addresses.

### Proposed Fix

- Represent an address selector as one or more CIDRs, or add an explicit `Any`
  selector variant.
- Ensure omitted selectors match both IPv4 and IPv6.
- Decide how explicit `0.0.0.0/0` should behave:
  - keep it IPv4-only and document that operators should add `::/0`, or
  - introduce an `any` keyword for dual-stack matching.
- Update README and sample config guidance for dual-stack deployments.

### Validation

- Add ACL tests for omitted selectors matching IPv6 clients and destinations.
- Add config parsing tests for explicit IPv4-only, IPv6-only, and dual-stack
  rules.
- Add an integration test for IPv6 CONNECT when the platform supports IPv6
  loopback.

## 4. Reject Non-Zero Reserved Bytes

### Concern

SOCKS5 request and UDP headers contain reserved fields that must be zero. The
current parser tolerates non-zero values.

This is primarily a protocol compliance and hardening issue. Rejecting malformed
frames reduces ambiguity and makes evasion attempts easier to reason about.

### Proposed Fix

- In SOCKS request parsing, return a protocol error when `RSV != 0x00`.
- In UDP header parsing, return a protocol error when the two-byte reserved
  field is not `0x0000`.
- Preserve the current behavior of dropping malformed UDP datagrams without
  tearing down the association.

### Validation

- Add parser unit tests for non-zero request `RSV`.
- Add parser unit tests for non-zero UDP `RSV`.
- Add an integration test confirming malformed requests receive a failure or
  closed connection instead of being serviced.

## 5. Expand Coverage Around Authentication and UDP Relay Behavior

### Concern

The existing test suite covers the happy-path CONNECT flow, a denial path, and
the UDP ASSOCIATE handshake. It does not yet exercise full UDP forwarding,
malformed protocol frames, slow-client behavior, or username/password failures
end to end.

### Proposed Fix

- Add integration tests for username/password success and failure.
- Add integration tests for full UDP ASSOCIATE forwarding.
- Add malformed-frame tests for request RSV, UDP RSV, unknown commands, invalid
  address types, and empty domain names.
- Add timeout/resource tests once the handshake timeout exists.

### Validation

- Run `cargo test` locally after each change.
- Keep tests deterministic by using loopback listeners and short, explicit
  timeouts.

## Suggested Implementation Order

1. Add handshake/request timeout support.
2. Add UDP endpoint locking.
3. Fix address selector semantics for dual-stack behavior.
4. Enforce reserved-byte validation.
5. Fill the remaining authentication, UDP, and malformed-frame test gaps.
