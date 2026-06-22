//! The access-control engine.
//!
//! Alighieri's rule model is inspired by Dante's `client`/`socks` rule blocks.
//! Rules are evaluated top-to-bottom and the **first matching rule wins**. If
//! no rule matches, the request is denied — Alighieri is deny-by-default, which
//! is the secure posture for an internet-facing proxy.
//!
//! Two rule scopes exist:
//!
//! - [`Scope::Client`]: evaluated when a TCP connection is accepted. It decides
//!   *who may talk to the proxy at all* (matched on the client's source address
//!   and the proxy's accepting address).
//! - [`Scope::Socks`]: evaluated once a SOCKS5 request has been parsed. It
//!   decides *what an authenticated client may ask the proxy to do* (matched on
//!   source, destination, command, protocol and negotiated auth method).

use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{AuthKind, Protocol, RateLimit};
use crate::net::AddrSpec;
use crate::socks5::Command;

/// Whether a matching rule allows or denies the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Pass,
    Block,
}

/// The phase at which a rule applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// `client` rules — connection admission.
    Client,
    /// `socks` rules — per-request authorisation.
    Socks,
}

/// A single access-control rule.
///
/// Optional selector fields (`commands`, `protocols`, `methods`) act as "any"
/// when empty: an empty `commands` list matches every command.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Optional operator-provided rule name for logs and metrics.
    pub name: Option<Arc<str>>,
    pub verdict: Verdict,
    pub scope: Scope,
    /// Source (client) address selector.
    pub from: AddrSpec,
    /// Destination selector. For `client` rules this is the proxy's own
    /// accepting address; for `socks` rules it is the request destination.
    pub to: AddrSpec,
    /// Allowed commands; empty means "any command".
    pub commands: Vec<Command>,
    /// Allowed protocols; empty means "any protocol".
    pub protocols: Vec<Protocol>,
    /// Allowed auth methods; empty means "any method".
    pub methods: Vec<AuthKind>,
    /// Optional per-session bandwidth limit (`socks` rules only): each matching
    /// CONNECT relay is shaped to this rate. `None` means unlimited.
    pub bandwidth: Option<RateLimit>,
    /// 1-based line number in the source config (for diagnostics).
    pub source_line: usize,
}

/// Context for evaluating a [`Scope::Client`] rule (connection admission).
#[derive(Debug, Clone, Copy)]
pub struct ClientContext {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub proxy_ip: IpAddr,
    pub proxy_port: u16,
}

/// Context for evaluating a [`Scope::Socks`] rule (request authorisation).
#[derive(Debug, Clone, Copy)]
pub struct SocksContext<'a> {
    pub client_ip: IpAddr,
    pub client_port: u16,
    /// The hostname the client requested, if it sent a domain rather than an IP
    /// literal. Matched against `to:` hostname patterns before resolution.
    pub dest_host: Option<&'a str>,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub command: Command,
    pub protocol: Protocol,
    pub method: AuthKind,
}

/// Access-control decision including the source line and optional name of the
/// matching rule. A missing source line means deny-by-default; a missing name
/// can also mean the matching rule was simply unnamed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDecision {
    pub verdict: Verdict,
    pub source_line: Option<usize>,
    pub rule_name: Option<Arc<str>>,
    /// The matching `socks` rule's per-session bandwidth limit, if any.
    pub bandwidth: Option<RateLimit>,
}

impl Rule {
    fn matches_client(&self, ctx: &ClientContext) -> bool {
        self.scope == Scope::Client
            && self.from.matches(ctx.client_ip, ctx.client_port)
            && self.to.matches(ctx.proxy_ip, ctx.proxy_port)
    }

    fn matches_socks(&self, ctx: &SocksContext<'_>) -> bool {
        self.scope == Scope::Socks
            && self.from.matches(ctx.client_ip, ctx.client_port)
            && self
                .to
                .matches_dest(ctx.dest_host, ctx.dest_ip, ctx.dest_port)
            && (self.commands.is_empty() || self.commands.contains(&ctx.command))
            && (self.protocols.is_empty() || self.protocols.contains(&ctx.protocol))
            && (self.methods.is_empty() || self.methods.contains(&ctx.method))
    }
}

/// An ordered collection of rules with first-match-wins, deny-by-default
/// evaluation.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Builds a rule set from a vector of rules.
    pub fn new(rules: Vec<Rule>) -> Self {
        RuleSet { rules }
    }

    /// Evaluates connection admission. Returns the matching rule's verdict, or
    /// `Block` if no `client` rule matches.
    pub fn evaluate_client(&self, ctx: &ClientContext) -> Verdict {
        self.evaluate_client_detail(ctx).verdict
    }

    /// Evaluates connection admission and includes the matching rule line.
    pub fn evaluate_client_detail(&self, ctx: &ClientContext) -> RuleDecision {
        for rule in &self.rules {
            if rule.matches_client(ctx) {
                return RuleDecision {
                    verdict: rule.verdict,
                    source_line: Some(rule.source_line),
                    rule_name: rule.name.clone(),
                    // `client` rules carry no bandwidth limit.
                    bandwidth: None,
                };
            }
        }
        RuleDecision {
            verdict: Verdict::Block,
            source_line: None,
            rule_name: None,
            bandwidth: None,
        }
    }

    /// Evaluates request authorisation. Returns the matching rule's verdict, or
    /// `Block` if no `socks` rule matches.
    pub fn evaluate_socks(&self, ctx: &SocksContext<'_>) -> Verdict {
        self.evaluate_socks_detail(ctx).verdict
    }

    /// Whether any `pass` rule could authorise a `UdpAssociate` for this client,
    /// ignoring the not-yet-known datagram destination.
    ///
    /// Used to reject a UDP ASSOCIATE up front — before binding sockets and
    /// replying success — when the policy categorically forbids UDP for the
    /// client (e.g. only `command: connect` rules), so such a client cannot hold
    /// a relay socket open until the idle timeout. It is deliberately permissive
    /// about the destination: a client with at least one UDP-permitting rule is
    /// admitted and the per-datagram authoriser still filters the actual targets,
    /// so destination-restricted UDP configs are never falsely rejected here.
    pub fn udp_associate_reachable(
        &self,
        client_ip: IpAddr,
        client_port: u16,
        method: AuthKind,
    ) -> bool {
        self.rules.iter().any(|rule| {
            rule.scope == Scope::Socks
                && rule.verdict == Verdict::Pass
                && rule.from.matches(client_ip, client_port)
                && (rule.commands.is_empty() || rule.commands.contains(&Command::UdpAssociate))
                && (rule.protocols.is_empty() || rule.protocols.contains(&Protocol::Udp))
                && (rule.methods.is_empty() || rule.methods.contains(&method))
        })
    }

    /// Evaluates request authorisation and includes the matching rule line.
    pub fn evaluate_socks_detail(&self, ctx: &SocksContext<'_>) -> RuleDecision {
        for rule in &self.rules {
            if rule.matches_socks(ctx) {
                return RuleDecision {
                    verdict: rule.verdict,
                    source_line: Some(rule.source_line),
                    rule_name: rule.name.clone(),
                    bandwidth: rule.bandwidth.clone(),
                };
            }
        }
        RuleDecision {
            verdict: Verdict::Block,
            source_line: None,
            rule_name: None,
            bandwidth: None,
        }
    }

    /// Returns `true` if the rule set contains at least one rule of the given
    /// scope. Used to warn operators about configs that would deny everything.
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.rules.iter().any(|r| r.scope == scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(cidr: &str) -> AddrSpec {
        AddrSpec::new(cidr.parse().unwrap(), None)
    }

    fn client_rule(verdict: Verdict, from: &str) -> Rule {
        Rule {
            name: None,
            verdict,
            scope: Scope::Client,
            from: spec(from),
            to: spec("0.0.0.0/0"),
            commands: vec![],
            protocols: vec![],
            methods: vec![],
            bandwidth: None,
            source_line: 0,
        }
    }

    fn socks_rule(verdict: Verdict, to: &str, commands: Vec<Command>) -> Rule {
        Rule {
            name: None,
            verdict,
            scope: Scope::Socks,
            from: spec("0.0.0.0/0"),
            to: spec(to),
            commands,
            protocols: vec![],
            methods: vec![],
            bandwidth: None,
            source_line: 0,
        }
    }

    fn client_ctx(ip: &str) -> ClientContext {
        ClientContext {
            client_ip: ip.parse().unwrap(),
            client_port: 5000,
            proxy_ip: "0.0.0.0".parse().unwrap(),
            proxy_port: 1080,
        }
    }

    fn socks_ctx(dest: &str, cmd: Command) -> SocksContext<'static> {
        SocksContext {
            client_ip: "10.0.0.5".parse().unwrap(),
            client_port: 5000,
            dest_host: None,
            dest_ip: dest.parse().unwrap(),
            dest_port: 443,
            command: cmd,
            protocol: Protocol::Tcp,
            method: AuthKind::None,
        }
    }

    fn socks_ctx_host<'a>(host: &'a str, dest: &str, cmd: Command) -> SocksContext<'a> {
        SocksContext {
            dest_host: Some(host),
            ..socks_ctx(dest, cmd)
        }
    }

    #[test]
    fn udp_associate_reachable_gates_on_command() {
        // Only CONNECT permitted: UDP is categorically unreachable, so an
        // ASSOCIATE is rejected before any socket is bound.
        let connect_only = RuleSet::new(vec![socks_rule(
            Verdict::Pass,
            "0.0.0.0/0",
            vec![Command::Connect],
        )]);
        assert!(!connect_only.udp_associate_reachable(
            "10.0.0.5".parse().unwrap(),
            5000,
            AuthKind::None
        ));

        // A UDP-permitting rule admits the association even if its destination is
        // narrow (the per-datagram authoriser still filters actual targets).
        let with_udp = RuleSet::new(vec![socks_rule(
            Verdict::Pass,
            "10.0.0.0/8",
            vec![Command::UdpAssociate],
        )]);
        assert!(with_udp.udp_associate_reachable(
            "10.0.0.5".parse().unwrap(),
            5000,
            AuthKind::None
        ));

        // An "any command" rule (empty list) also permits UDP.
        let any_cmd = RuleSet::new(vec![socks_rule(Verdict::Pass, "0.0.0.0/0", vec![])]);
        assert!(any_cmd.udp_associate_reachable("10.0.0.5".parse().unwrap(), 5000, AuthKind::None));

        // A `block` rule does not count as reachability.
        let blocked = RuleSet::new(vec![socks_rule(
            Verdict::Block,
            "0.0.0.0/0",
            vec![Command::UdpAssociate],
        )]);
        assert!(!blocked.udp_associate_reachable(
            "10.0.0.5".parse().unwrap(),
            5000,
            AuthKind::None
        ));
    }

    #[test]
    fn socks_rule_matches_requested_hostname() {
        use crate::net::HostPattern;
        let rs = RuleSet::new(vec![Rule {
            name: None,
            verdict: Verdict::Pass,
            scope: Scope::Socks,
            from: AddrSpec::any(),
            to: AddrSpec::host(HostPattern::Suffix("example.com".into()), None),
            commands: vec![],
            protocols: vec![],
            methods: vec![],
            bandwidth: None,
            source_line: 1,
        }]);

        // The requested host (or a subdomain) is allowed regardless of the IP.
        assert_eq!(
            rs.evaluate_socks(&socks_ctx_host(
                "api.example.com",
                "203.0.113.7",
                Command::Connect
            )),
            Verdict::Pass
        );
        // A different host, even resolving to the same IP, does not match.
        assert_eq!(
            rs.evaluate_socks(&socks_ctx_host("evil.com", "203.0.113.7", Command::Connect)),
            Verdict::Block
        );
        // An IP-literal request (no hostname) never matches a hostname rule.
        assert_eq!(
            rs.evaluate_socks(&socks_ctx("203.0.113.7", Command::Connect)),
            Verdict::Block
        );
    }

    #[test]
    fn socks_decision_carries_rule_bandwidth() {
        // A CONNECT-only rule with a bandwidth limit.
        let mut rule = socks_rule(Verdict::Pass, "0.0.0.0/0", vec![Command::Connect]);
        rule.bandwidth = Some(RateLimit {
            limit: 1024,
            window: std::time::Duration::from_secs(1),
        });
        let rs = RuleSet::new(vec![rule]);

        // A matching request surfaces the rule's bandwidth.
        let allowed = rs.evaluate_socks_detail(&socks_ctx("8.8.8.8", Command::Connect));
        assert_eq!(allowed.verdict, Verdict::Pass);
        assert_eq!(allowed.bandwidth.as_ref().map(|b| b.limit), Some(1024));

        // A non-matching request denies by default, with no bandwidth.
        let denied = rs.evaluate_socks_detail(&socks_ctx("8.8.8.8", Command::UdpAssociate));
        assert_eq!(denied.verdict, Verdict::Block);
        assert_eq!(denied.bandwidth, None);
    }

    #[test]
    fn deny_by_default_when_empty() {
        let rs = RuleSet::default();
        assert_eq!(rs.evaluate_client(&client_ctx("1.2.3.4")), Verdict::Block);
        assert_eq!(
            rs.evaluate_socks(&socks_ctx("8.8.8.8", Command::Connect)),
            Verdict::Block
        );
    }

    #[test]
    fn first_match_wins() {
        let rs = RuleSet::new(vec![
            client_rule(Verdict::Block, "10.0.0.0/8"),
            client_rule(Verdict::Pass, "0.0.0.0/0"),
        ]);
        // 10.x hits the block rule first.
        assert_eq!(rs.evaluate_client(&client_ctx("10.0.0.5")), Verdict::Block);
        // Other addresses fall through to the pass rule.
        assert_eq!(rs.evaluate_client(&client_ctx("8.8.8.8")), Verdict::Pass);
    }

    #[test]
    fn detailed_decision_includes_rule_line() {
        let mut rule = client_rule(Verdict::Pass, "0.0.0.0/0");
        rule.source_line = 42;
        let rs = RuleSet::new(vec![rule]);

        let decision = rs.evaluate_client_detail(&client_ctx("8.8.8.8"));

        assert_eq!(decision.verdict, Verdict::Pass);
        assert_eq!(decision.source_line, Some(42));
        assert_eq!(decision.rule_name, None);
    }

    #[test]
    fn detailed_decision_includes_rule_name() {
        let mut rule = client_rule(Verdict::Pass, "0.0.0.0/0");
        rule.name = Some(Arc::from("lan-clients"));
        let rs = RuleSet::new(vec![rule]);

        let decision = rs.evaluate_client_detail(&client_ctx("8.8.8.8"));

        assert_eq!(decision.rule_name.as_deref(), Some("lan-clients"));
    }

    #[test]
    fn socks_command_filtering() {
        let rs = RuleSet::new(vec![socks_rule(
            Verdict::Pass,
            "0.0.0.0/0",
            vec![Command::Connect],
        )]);
        assert_eq!(
            rs.evaluate_socks(&socks_ctx("8.8.8.8", Command::Connect)),
            Verdict::Pass
        );
        // UDP associate is not in the allowed command list → no match → deny.
        assert_eq!(
            rs.evaluate_socks(&socks_ctx("8.8.8.8", Command::UdpAssociate)),
            Verdict::Block
        );
    }

    #[test]
    fn socks_dest_filtering_blocks_loopback() {
        let rs = RuleSet::new(vec![
            socks_rule(Verdict::Block, "127.0.0.0/8", vec![]),
            socks_rule(Verdict::Pass, "0.0.0.0/0", vec![]),
        ]);
        assert_eq!(
            rs.evaluate_socks(&socks_ctx("127.0.0.1", Command::Connect)),
            Verdict::Block
        );
        assert_eq!(
            rs.evaluate_socks(&socks_ctx("93.184.216.34", Command::Connect)),
            Verdict::Pass
        );
    }

    #[test]
    fn has_scope_detection() {
        let rs = RuleSet::new(vec![client_rule(Verdict::Pass, "0.0.0.0/0")]);
        assert!(rs.has_scope(Scope::Client));
        assert!(!rs.has_scope(Scope::Socks));
    }
}
