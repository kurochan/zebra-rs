# Policy

A *policy* in zebra-rs is the equivalent of what Cisco / Juniper /
FRR call a *route-map* or *route-policy*. It is an ordered list of
entries; each entry decides whether a route is accepted, rejected,
or modified before being passed on. A policy is attached to a BGP
peer per address-family — under `neighbor X afi-safi <family>
policy` — in either the `in` direction (applied to routes received
from the peer) or the `out` direction (applied to routes advertised
to the peer).

A policy is built out of three pieces:

- **Control flow** — each entry has a mandatory `action`: `permit`,
  `next`, or `deny`. The action decides what happens after the
  entry's match clauses succeed.
- **Match** — zero or more conditions the route must satisfy for
  the entry to fire. Conditions are AND'd together.
- **Set** — zero or more modifications to apply to the route's
  attributes when the entry fires (and the action is not `deny`).

Most policy clauses reference a *set* — a separately-named
collection of values. The defined set types are:

- `prefix-set` — IP prefixes, optionally with `le`/`ge` length
  bounds. Used by `match prefix-set`.
- `community-set` — standard or extended community values, with
  optional regex. Used by `match community`.
- `ext-community-set` — extended communities only (`rt:`/`soo:`),
  with optional regex. Used by `match ext-community`.
- `large-community-set` — RFC 8092 large communities, with optional
  regex. Used by `match large-community`.
- `as-path-set` — regex against the AS_PATH. Used by
  `match as-path`.

A complete policy that prefers routes from a specific peer subnet
and tags them with a community looks like this:

```console
prefix-set CUSTOMER-A {
    prefix 10.0.0.0/8 {
        le 32;
    };
}

community-set TAG-CUST-A {
    members {
        65001:100;
    }
}

policy IN-CUSTOMER-A {
    entry 10 {
        action permit;
        match {
            prefix-set CUSTOMER-A;
        }
        set {
            local-preference {
                set 200;
            }
            community {
                name TAG-CUST-A;
                additive;
            }
        }
    }
}

router bgp {
    neighbor 192.168.0.1 {
        afi-safi ipv4 {
            policy {
                in IN-CUSTOMER-A;
            }
        }
    }
}
```

The next three sections cover control flow, match, and set in
detail, with worked examples for every clause.

## Per-VRF BGP neighbor prefix-sets

A BGP neighbor inside a VRF can bind a named prefix-set independently
for each address family and direction. Only matching prefixes are
accepted or advertised. A configured name that does not currently
resolve is fail-close: no routes pass that direction until the
prefix-set exists. With no binding, the existing unfiltered behavior is
preserved.

```yaml
prefix-set:
- name: PEER-IN-V4
  prefixes:
  - prefix: 0.0.0.0/0
  - prefix: 203.0.113.0/24
    le: 32
- name: PEER-OUT-V4
  prefixes:
  - prefix: 198.51.100.0/24

router:
  bgp:
    global:
      as: 65001
      router-id: 192.0.2.1
    vrf:
    - name: vrf-blue
      neighbor:
      - remote-address: 192.0.2.2
        remote-as: 65002
        afi-safi:
        - name: ipv4
          enabled: true
          prefix-set:
            in: PEER-IN-V4
            out: PEER-OUT-V4
```

The equivalent block configuration is:

```console
router bgp {
    vrf vrf-blue {
        neighbor 192.0.2.2 {
            remote-as 65002;
            afi-safi ipv4 {
                enabled true;
                prefix-set {
                    in PEER-IN-V4;
                    out PEER-OUT-V4;
                }
            }
        }
    }
}
```

The set/delete forms address one direction at a time:

```console
set router bgp vrf vrf-blue neighbor 192.0.2.2 afi-safi ipv4 prefix-set in PEER-IN-V4
set router bgp vrf vrf-blue neighbor 192.0.2.2 afi-safi ipv4 prefix-set out PEER-OUT-V4
delete router bgp vrf vrf-blue neighbor 192.0.2.2 afi-safi ipv4 prefix-set in PEER-IN-V4
delete router bgp vrf vrf-blue neighbor 192.0.2.2 afi-safi ipv4 prefix-set out PEER-OUT-V4
```

Binding changes and edits to the referenced prefix-set are applied to
an established session without resetting it. Inbound routes retained in
Adj-RIB-In are replayed; outbound changes advertise newly permitted
routes and withdraw routes that are no longer permitted. IPv6 uses the
same configuration under `afi-safi ipv6`.

Inspect a single CE peer with `show bgp vrf vrf-blue neighbor
192.0.2.2`. The text view reports each configured family and marks an
unresolved name explicitly:

```text
Address family: IPv4 Unicast
  Prefix-set in:  PEER-IN-V4
  Prefix-set out: PEER-OUT-V4 (unresolved)
```

The JSON view carries the same state in `policy_bindings`, including
`prefix_set_in_resolved` and `prefix_set_out_resolved` booleans.
