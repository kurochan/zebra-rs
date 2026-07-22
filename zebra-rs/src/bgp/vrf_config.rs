//! Per-VRF BGP configuration staging.
//!
//! The callbacks in this module fan out the YANG paths under
//! `/router/bgp/vrf/<name>/...` (zebra-bgp-vrf.yang) into a single
//! [`BgpVrfConfig`] per VRF, stored on `Bgp::vrfs`. The per-VRF
//! runtime consumes this map to spawn tasks and materialize peers.
//!
//! Design notes:
//!
//! - VRF entries are created lazily: a callback for any leaf under
//!   `vrf <NAME>` inserts a default entry if missing. That matches
//!   the order YANG callbacks fire in, which is depth-first by path
//!   — the list-key handler typically arrives first, but staging
//!   tolerates the leaf handler racing ahead.
//! - The `peer-group` reference is a plain string (matching the
//!   schema). Resolution against `neighbor-group <X>` (remote-as
//!   fallback + afi-safi opinions) happens when the per-VRF runtime
//!   materializes peers.
//! - The label-mode value is parsed at the callback boundary into a
//!   typed enum; bad input fails the callback and is rejected by the
//!   config commit (same shape every other `enum`-typed leaf uses).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use bgp_packet::{Afi, AfiSafi, RouteDistinguisher, Safi};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::bgp_vrf_trace;
use crate::config::{Args, ConfigOp};

use super::Bgp;
use super::config::BgpRedistSource;
use super::policy::InOut;
use super::vrf::msg::BgpVrfMsg;
use crate::rib::RedistAfi;

/// MPLS label allocation strategy for VPN routes originated from a
/// VRF — mirrors `label-mode` in zebra-bgp-vrf.yang. Default is
/// `Vrf` (one label per VRF, lowest label churn). Variant names
/// drop the redundant `Per`-prefix that the YANG values carry; the
/// `parse` helper bridges back to the wire form.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BgpVrfLabelMode {
    #[default]
    Vrf,
    Route,
    Nexthop,
}

impl BgpVrfLabelMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "per-vrf" => Some(Self::Vrf),
            "per-route" => Some(Self::Route),
            "per-nexthop" => Some(Self::Nexthop),
            _ => None,
        }
    }
}

/// VPN data-plane encapsulation for a VRF — mirrors `encapsulation`
/// in zebra-bgp-vrf.yang. Default `Mpls` (RFC 4364 service label).
/// `Srv6` (RFC 9252) binds a per-VRF End.DT46 service SID from the
/// `segment-routing srv6 locator` instead of an MPLS label, and the
/// PE programs a seg6local decap rather than an AF_MPLS ILM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BgpVrfEncapsulation {
    #[default]
    Mpls,
    Srv6,
    /// EVPN symmetric IRB (RFC 9135): a Type-5 carries an L3VNI (the NLRI
    /// label) + this PE's router MAC (a Router's-MAC EC), routed over VXLAN.
    Vxlan,
}

impl BgpVrfEncapsulation {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "mpls" => Some(Self::Mpls),
            "srv6" => Some(Self::Srv6),
            "vxlan" => Some(Self::Vxlan),
            _ => None,
        }
    }
}

/// Per-peer attribute set for a CE peer configured under
/// `router bgp vrf X neighbor <addr>`. Mirrors `bgp-vrf-neighbor` in
/// zebra-bgp-vrf.yang.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgpVrfPrefixSetConfig {
    pub input: Option<String>,
    pub output: Option<String>,
}

impl BgpVrfPrefixSetConfig {
    fn get(&self, direction: InOut) -> &Option<String> {
        match direction {
            InOut::Input => &self.input,
            InOut::Output => &self.output,
        }
    }

    fn get_mut(&mut self, direction: InOut) -> &mut Option<String> {
        match direction {
            InOut::Input => &mut self.input,
            InOut::Output => &mut self.output,
        }
    }
}

/// First-observed state for one per-VRF prefix-set binding during a config
/// transaction.  Config replacement arrives as Delete followed by Set; keeping
/// the value from before the first callback lets `CommitEnd` publish only the
/// final binding, without exposing the intermediate unbound state to the live
/// VRF task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingVrfPrefixSetChange {
    vrf: String,
    address: IpAddr,
    afi_safi: AfiSafi,
    direction: InOut,
    before: Option<String>,
}

/// Final, net changes produced from a config transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VrfPrefixSetChange {
    vrf: String,
    address: IpAddr,
    afi_safi: AfiSafi,
    direction: InOut,
    name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgpVrfNeighborConfig {
    pub remote_as: Option<u32>,
    pub peer_group: Option<String>,
    pub description: Option<String>,
    /// Verbatim per-family `afi-safi <name> enabled <bool>` statements
    /// for this CE peer — the per-VRF equivalent of
    /// [`super::peer::PeerConfig::mp_explicit`]. Only the IPv4 / IPv6
    /// unicast families are reachable from the schema. Empty means "no
    /// explicit override": the negotiated family is then derived from
    /// the peer's own address family in `materialize_peers`. There is
    /// Neighbor-group AFI/SAFI opinions are resolved at materialization
    /// beneath this map, so an explicit per-neighbor statement wins.
    pub mp_explicit: BTreeMap<AfiSafi, bool>,
    /// Staged `timers { … }` for this CE peer, copied verbatim onto
    /// [`super::peer::PeerConfig::timer`] by `materialize_peers`.
    ///
    /// Deliberately the *same* type the peer holds rather than a
    /// narrower struct: the schema only exposes the three leaves the
    /// timer code actually consumes (connect-retry-time, hold-time,
    /// idle-hold-time), so the rest stay `None` — which is what they
    /// would be anyway, since nothing reads them even on the global
    /// neighbor. Sharing the type means wiring one of those up later
    /// is a schema-only change here.
    pub timer: super::timer::Config,
    /// Per-family inbound/outbound named prefix-set references. Names stay
    /// staged even while unresolved; the running per-VRF task resolves them
    /// through the policy actor and treats an unresolved binding as deny-all.
    pub prefix_set: BTreeMap<AfiSafi, BgpVrfPrefixSetConfig>,
}

/// Per-AFI knobs under `router bgp vrf X afi-safi {ipv4,ipv6}-unicast`.
/// Generic on the prefix type so the same struct holds either v4 or
/// v6 networks.
#[derive(Debug, Clone)]
pub struct BgpVrfAfConfig<N: Ord> {
    pub networks: BTreeSet<N>,
    /// Redistribution sources enabled for this VRF/AFI
    /// (`afi-safi {ipv4,ipv6} redistribute {connected,static}`). Each
    /// pulls the VRF table's routes of that protocol into the per-VRF
    /// Loc-RIB for VPNv4/v6 export. Bare presence today (no per-source
    /// modifiers).
    pub redistribute: BTreeSet<BgpRedistSource>,
}

impl<N: Ord> Default for BgpVrfAfConfig<N> {
    fn default() -> Self {
        Self {
            networks: BTreeSet::new(),
            redistribute: BTreeSet::new(),
        }
    }
}

/// SRv6 mobile user-plane direction for a per-VRF MUP service
/// (zebra-bgp-vrf.yang `afi-safi mup route {st1|st2}`). `Decapsulation`
/// is the `st2` egress/uplink (Type-2 ST, the N3 side); `Encapsulation`
/// is the `st1` ingress/downlink (Type-1 ST, the N6 side). Ordered so it
/// can key the per-direction `routes` map on [`BgpVrfMobileUplane`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MupSrv6Direction {
    Decapsulation,
    Encapsulation,
}

/// MUP Segment Discovery route type for a per-VRF service — the PE side
/// (zebra-bgp-vrf.yang `afi-safi mup segment {direct|interwork}`).
/// `Direct` originates a Direct Segment Discovery (DSD, type 2) route
/// carrying the VRF's End.DT46 SID; `Interwork` an Interwork Segment
/// Discovery (ISD, type 1) route. Independent of [`MupRouteBinding`], which
/// is the controller-side Session-Transformed origination binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MupSegmentMode {
    Direct,
    Interwork,
}

impl MupSegmentMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "direct" => Some(Self::Direct),
            "interwork" => Some(Self::Interwork),
            _ => None,
        }
    }
}

/// MUP forwarding-plane behaviour for a per-VRF service (`afi-safi mup
/// dataplane {end-dt46|gtp}`). `EndDt46` (default) installs the SRv6 End.DT46
/// stand-in into the mainline kernel; `Gtp` programs a real GTP-U tunnel from
/// the ST route's endpoint + TEID via the cradle eBPF forwarder. The control
/// plane is identical either way — this selects only the endpoint behaviour
/// advertised and the FIB-install target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MupDataplane {
    #[default]
    EndDt46,
    Gtp,
}

impl MupDataplane {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "end-dt46" => Some(Self::EndDt46),
            "gtp" => Some(Self::Gtp),
            _ => None,
        }
    }
}

/// One `afi-safi mup route {st1|st2} { network-instance <ni>;
/// [mup-ext-comm <2:4>;] }` list entry for one VRF: the session
/// network-instance matched, and (st2 only) the Direct-segment MUP
/// Extended Community the originated ST2 routes resolve to. Keyed by
/// its [`MupSrv6Direction`] in [`BgpVrfMobileUplane::routes`], so one
/// VRF may bind BOTH directions and serve a bidirectional UPF behind a
/// single N6 interface (issue #1947). Surfaced in `show bgp mup` (the
/// `MUP VRFs:` block) and consumed by the P5 MUP controller when it
/// originates ST routes (st2/Decapsulation → Type-2 ST;
/// st1/Encapsulation → Type-1 ST).
#[derive(Default, Debug, Clone)]
pub struct MupRouteBinding {
    pub network_instance: Option<String>,
    /// `afi-safi mup route st2 mup-ext-comm <2:4>` — the BGP MUP Extended
    /// Community (Direct-Type Segment Identifier, draft-mpmz-bess-mup-safi
    /// §3.2 / §3.3.10) attached to the Type-2 ST routes this VRF
    /// originates, so a receiving PE resolves the (endpoint, TEID) tunnel
    /// onto the matching End.DT46 Direct segment. Meaningful only on the
    /// Decapsulation (st2) binding; `None` for st1.
    pub mup_ext_comm: Option<RouteDistinguisher>,
}

/// Per-VRF BGP MUP (draft-ietf-bess-mup-safi) service config — the `mup`
/// container under `router bgp vrf <name>` in zebra-bgp-vrf.yang. Holds
/// only the `route {st1|st2}` origination binding; the export/import
/// route-targets live on the top-level `vrf <name> mup
/// route-target {export|import}` (RIB-owned, surfaced to BGP via
/// `rib_known_vrfs`), the same framework as ipv4 / ipv6.
#[derive(Default, Debug, Clone)]
pub struct BgpVrfMobileUplane {
    /// `afi-safi mup route {st1|st2}` — the controller-side ST origination
    /// bindings, keyed by direction. One VRF may carry both an `st1` and an
    /// `st2` entry (a bidirectional UPF behind a single N6 interface/VRF,
    /// issue #1947); the two-VRF split (one direction each) remains valid.
    pub routes: BTreeMap<MupSrv6Direction, MupRouteBinding>,
    /// `afi-safi mup segment {direct|interwork}` — PE-side Segment
    /// Discovery origination for this VRF. `Direct` → DSD (type 2, NLRI =
    /// RD + router-id); `Interwork` → ISD (type 1, NLRI = RD +
    /// [`Self::interwork_prefix`]). Both carry the VRF's End.DT46 SID.
    /// Independent of `routes`.
    pub segment: Option<MupSegmentMode>,
    /// `afi-safi mup segment direct mup-ext-comm <2:4>` — the BGP MUP
    /// Extended Community (transitive type 0x0c, sub-type 0x00 =
    /// Direct-Type Segment Identifier, draft-mpmz-bess-mup-safi §3.2)
    /// identifying this VRF's Direct segment. Attached to the VRF's DSD
    /// route and to the controller's Type-2 ST routes that resolve to
    /// this Direct segment (§3.3.10 / §3.3.12). The 6-octet value reuses
    /// the RD/RT 2:4 wire layout, so it is stored as a `RouteDistinguisher`.
    pub mup_ext_comm: Option<RouteDistinguisher>,
    /// `afi-safi mup segment interwork prefix <p>` — the interwork segment
    /// prefix advertised in this VRF's Interwork Segment Discovery (ISD,
    /// type 1) route NLRI (draft-mpmz-bess-mup-safi §3.1.1), typically the
    /// locally connected gNodeB N3 prefix. Meaningful only under the
    /// `interwork` segment; the ISD does not originate until it is set, and
    /// its AFI follows this prefix's family.
    pub interwork_prefix: Option<IpNet>,
    /// `afi-safi mup dataplane {end-dt46|gtp}` — the forwarding-plane
    /// behaviour for this VRF's MUP service. `EndDt46` (default) installs the
    /// SRv6 End.DT46 stand-in into the mainline kernel; `Gtp` programs a real
    /// GTP-U tunnel from the resolved ST route's endpoint + TEID via the
    /// cradle eBPF forwarder.
    pub dataplane: MupDataplane,
}

/// Staged candidate configuration for one VRF entry. Mirrors the
/// `list vrf` body in zebra-bgp-vrf.yang.
#[derive(Default, Debug, Clone)]
pub struct BgpVrfConfig {
    pub rd: Option<RouteDistinguisher>,
    pub router_id: Option<Ipv4Addr>,
    pub label_mode: BgpVrfLabelMode,
    pub encapsulation: BgpVrfEncapsulation,
    pub neighbors: BTreeMap<IpAddr, BgpVrfNeighborConfig>,
    pub ipv4_unicast: Option<BgpVrfAfConfig<Ipv4Net>>,
    pub ipv6_unicast: Option<BgpVrfAfConfig<Ipv6Net>>,
    /// Advertise this VRF's IPv4 routes as EVPN Type-5 (RFC 9136).
    /// Mirrors `evpn advertise-ipv4` in zebra-bgp-vrf.yang.
    pub evpn_advertise_v4: bool,
    /// Advertise this VRF's IPv6 routes as EVPN Type-5 (RFC 9136).
    pub evpn_advertise_v6: bool,
    /// EVPN symmetric-IRB L3VNI for this VRF (RFC 9135): stamped as the
    /// Type-5 NLRI label. Mirrors `evpn l3vni` in zebra-bgp-vrf.yang.
    pub l3vni: Option<u32>,
    /// This PE's router MAC for the L3VNI — attached to originated Type-5
    /// routes as a Router's-MAC EC. Mirrors `evpn router-mac`.
    pub router_mac: Option<[u8; 6]>,
    /// Inter-AS MPLS/VPN Option AB (RFC 4364 hybrid of §10a/§10b).
    /// Mirrors `inter-as-hybrid` in zebra-bgp-vrf.yang. When set, the
    /// VRF re-exports the VPNv4 routes it *imports* (not only `network`/
    /// CE-learned ones), so an ASBR relays a remote AS's VPN routes to
    /// its own PEs over a single MP-eBGP VPNv4 session while still
    /// forwarding per-VRF. Default `false` (ordinary L3VPN VRF).
    pub inter_as_hybrid: bool,
    /// Per-VRF BGP MUP (draft-ietf-bess-mup-safi) service config. Mirrors the
    /// `mup` container in zebra-bgp-vrf.yang.
    pub mobile_uplane: BgpVrfMobileUplane,
}

/// Whether two candidate configs materialize the same long-lived VRF task.
/// Prefix-set bindings are deliberately excluded: they have an atomic live
/// update path. Network/redistribution and MUP route changes likewise have
/// dedicated runtime messages/reconciliation and must not reset CE sessions.
pub(crate) fn runtime_structure_eq(
    before: &BgpVrfConfig,
    before_groups: &BTreeMap<String, super::neighbor_group::NeighborGroup>,
    after: &BgpVrfConfig,
    after_groups: &BTreeMap<String, super::neighbor_group::NeighborGroup>,
) -> bool {
    let neighbor_structure =
        |cfg: &BgpVrfConfig, groups: &BTreeMap<String, super::neighbor_group::NeighborGroup>| {
            cfg.neighbors
                .iter()
                .map(|(address, neighbor)| {
                    let mut neighbor = neighbor.clone();
                    neighbor.prefix_set.clear();

                    // Compare what materialize_peers actually puts on the wire,
                    // not the spelling of the activation intent. For an IPv4
                    // neighbor, absent activation and explicit `ipv4 enabled
                    // true` both negotiate the same singleton MP set and must
                    // not reset an established session. Group opinions are part
                    // of the same resolution stack and therefore use their own
                    // transaction snapshots here.
                    let group = neighbor
                        .peer_group
                        .as_ref()
                        .and_then(|name| groups.get(name));
                    neighbor.remote_as = neighbor
                        .remote_as
                        .or_else(|| group.and_then(|group| group.remote_as));
                    let base = if address.is_ipv6() {
                        AfiSafi::new(Afi::Ip6, Safi::Unicast)
                    } else {
                        AfiSafi::new(Afi::Ip, Safi::Unicast)
                    };
                    let mut effective = BTreeMap::from([(base, true)]);
                    if let Some(group) = group {
                        for (family, opinion) in &group.afi_safi {
                            if opinion.enabled {
                                effective.insert(*family, true);
                            } else {
                                effective.remove(family);
                            }
                        }
                    }
                    for (family, enabled) in &neighbor.mp_explicit {
                        if *enabled {
                            effective.insert(*family, true);
                        } else {
                            effective.remove(family);
                        }
                    }
                    neighbor.mp_explicit = effective;
                    (*address, neighbor)
                })
                .collect::<BTreeMap<_, _>>()
        };

    before.rd == after.rd
        && before.router_id == after.router_id
        && before.label_mode == after.label_mode
        && before.encapsulation == after.encapsulation
        && neighbor_structure(before, before_groups) == neighbor_structure(after, after_groups)
        && before.evpn_advertise_v4 == after.evpn_advertise_v4
        && before.evpn_advertise_v6 == after.evpn_advertise_v6
        && before.l3vni == after.l3vni
        && before.router_mac == after.router_mac
        && before.inter_as_hybrid == after.inter_as_hybrid
        && before.mobile_uplane.dataplane == after.mobile_uplane.dataplane
}

/// Borrow the per-VRF entry on `Bgp::vrfs`, creating it for Set (the
/// "set leaf before set list-key" firing order makes lazy creation
/// necessary) but NEVER for Delete. A whole-subtree delete fires the
/// list-entry callback — which removes the map entry — before the
/// child-leaf delete callbacks, so a lazily re-created entry here
/// resurrected the VRF as a default config: `compute_vrf_diff` then
/// saw the name as still desired and the despawn (task teardown,
/// export purge, ILM withdraw, label reclaim) never ran. `None` on a
/// Delete for a gone VRF means "nothing left to mutate" — callbacks
/// early-return.
fn vrf_entry(bgp: &mut Bgp, name: String, op: ConfigOp) -> Option<&mut BgpVrfConfig> {
    match op {
        ConfigOp::Delete => bgp.vrfs.get_mut(&name),
        _ => Some(bgp.vrfs.entry(name).or_default()),
    }
}

/// `set router bgp vrf <NAME>` — list-key handler.
pub fn config_vrf(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            bgp.vrfs.entry(name).or_default();
        }
        ConfigOp::Delete => {
            bgp.vrfs.remove(&name);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> rd <RD>`.
pub fn config_vrf_rd(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let rd_str = args.string()?;
            cfg.rd = Some(RouteDistinguisher::from_str(&rd_str).ok()?);
        }
        ConfigOp::Delete => cfg.rd = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> router-id <IPv4>`.
pub fn config_vrf_router_id(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.router_id = Some(args.v4addr()?),
        ConfigOp::Delete => cfg.router_id = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> label-mode {per-vrf|per-route|per-nexthop}`.
pub fn config_vrf_label_mode(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            cfg.label_mode = BgpVrfLabelMode::parse(&raw)?;
        }
        ConfigOp::Delete => cfg.label_mode = BgpVrfLabelMode::default(),
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> encapsulation {mpls|srv6}`.
pub fn config_vrf_encapsulation(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            cfg.encapsulation = BgpVrfEncapsulation::parse(&raw)?;
        }
        ConfigOp::Delete => cfg.encapsulation = BgpVrfEncapsulation::default(),
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> inter-as-hybrid <BOOL>` — RFC 4364
/// Inter-AS Option AB. Enables re-export of imported VPNv4 routes for
/// this VRF (see [`BgpVrfConfig::inter_as_hybrid`]).
pub fn config_vrf_inter_as_hybrid(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.inter_as_hybrid = args.boolean()?,
        ConfigOp::Delete => cfg.inter_as_hybrid = false,
        _ => {}
    }
    Some(())
}

/// Map an `afi-safi mup route` list key (`st1`/`st2`) to the ST direction:
/// st1 = Encapsulation (downlink / N6 / ingress GTP encap), st2 =
/// Decapsulation (uplink / N3 / egress GTP decap).
fn mup_route_direction(key: &str) -> Option<MupSrv6Direction> {
    match key {
        "st1" => Some(MupSrv6Direction::Encapsulation),
        "st2" => Some(MupSrv6Direction::Decapsulation),
        _ => None,
    }
}

/// Borrow-or-create the per-VRF `route {st1|st2}` binding for the given
/// ST direction. Each direction is its own map entry, so one VRF may
/// bind both st1 and st2 (issue #1947); the `network-instance` /
/// `mup-ext-comm` child-leaf handlers accumulate into their direction's
/// binding regardless of the order their callbacks fire.
fn mup_route_binding(cfg: &mut BgpVrfConfig, direction: MupSrv6Direction) -> &mut MupRouteBinding {
    cfg.mobile_uplane.routes.entry(direction).or_default()
}

/// `set router bgp vrf <NAME> afi-safi mup route {st1|st2}` — list-key
/// handler. Establishes the ST direction binding (st1 = Encapsulation /
/// downlink, st2 = Decapsulation / uplink); the session network-instance
/// and (st2) the Direct-segment `mup-ext-comm` hang off child leaves.
/// The delete removes only that direction's entry, leaving a sibling
/// direction's binding intact.
pub fn config_vrf_mup_route(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let direction = mup_route_direction(&args.string()?)?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            mup_route_binding(cfg, direction);
        }
        ConfigOp::Delete => {
            cfg.mobile_uplane.routes.remove(&direction);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup route {st1|st2} network-instance
/// <NI>` — the PFCP session Network Instance this VRF originates ST routes
/// for. Matched against the session's Network Instance by the MUP
/// controller (st1 → Type-1 ST / ingress encap; st2 → Type-2 ST / egress
/// decap).
pub fn config_vrf_mup_route_network_instance(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let direction = mup_route_direction(&args.string()?)?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let ni = args.string()?;
            mup_route_binding(cfg, direction).network_instance = Some(ni);
        }
        ConfigOp::Delete => {
            if let Some(binding) = cfg.mobile_uplane.routes.get_mut(&direction) {
                binding.network_instance = None;
            }
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup route st2 mup-ext-comm <2:4>` —
/// the BGP MUP Extended Community (Direct-Type Segment Identifier) the
/// originated Type-2 ST routes resolve to (draft §3.3.10). Meaningful only
/// under `route st2` (Decapsulation); stored on that direction's binding.
pub fn config_vrf_mup_route_mup_ext_comm(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let direction = mup_route_direction(&args.string()?)?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            mup_route_binding(cfg, direction).mup_ext_comm =
                Some(RouteDistinguisher::from_str(&raw).ok()?);
        }
        ConfigOp::Delete => {
            if let Some(binding) = cfg.mobile_uplane.routes.get_mut(&direction) {
                binding.mup_ext_comm = None;
            }
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup segment {direct|interwork}` —
/// list-key handler for the `segment` list (keyed by the route type).
/// PE-side Segment Discovery origination. `direct` originates a Direct
/// Segment Discovery (DSD, type 2) route carrying the VRF's End.DT46 SID;
/// `interwork` an Interwork Segment Discovery (ISD, type 1) route. The
/// list key is the only token, so it is read before the op branch (the
/// `config_vrf_neighbor` pattern) and the delete only clears a matching
/// mode.
pub fn config_vrf_mup_segment(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let mode = MupSegmentMode::parse(&args.string()?)?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.mobile_uplane.segment = Some(mode),
        ConfigOp::Delete if cfg.mobile_uplane.segment == Some(mode) => {
            cfg.mobile_uplane.segment = None;
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup dataplane {end-dt46|gtp}` — the
/// MUP forwarding-plane behaviour for this VRF (the SRv6 End.DT46 stand-in vs
/// real GTP-U via cradle). Delete restores the default (End.DT46).
pub fn config_vrf_mup_dataplane(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let mode = MupDataplane::parse(&args.string()?)?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.mobile_uplane.dataplane = mode,
        ConfigOp::Delete => cfg.mobile_uplane.dataplane = MupDataplane::default(),
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup segment direct mup-ext-comm
/// <2:4>` — the BGP MUP Extended Community (Direct-Type Segment
/// Identifier) for this VRF's Direct segment. This leaf hangs off the
/// `segment` list, so the segment list key (`direct`/`interwork`) sits
/// between the VRF name and the value and is skipped here. The value is
/// the RD/RT 2:4 notation, stored as a `RouteDistinguisher` whose 6-octet
/// `val` maps straight onto the extended-community value.
pub fn config_vrf_mup_ext_comm(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let _segment = args.string()?; // segment list key (direct|interwork)
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            cfg.mobile_uplane.mup_ext_comm = Some(RouteDistinguisher::from_str(&raw).ok()?);
        }
        ConfigOp::Delete => cfg.mobile_uplane.mup_ext_comm = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup segment interwork prefix <p>` —
/// the interwork segment prefix carried in this VRF's Interwork Segment
/// Discovery (ISD, type 1) route NLRI (draft §3.1.1). Like `mup-ext-comm`,
/// this leaf hangs off the `segment` list, so the segment list key
/// (`direct`/`interwork`) sits between the VRF name and the value and is
/// skipped here. The value is an IPv4 or IPv6 prefix; the ISD's AFI follows
/// its family.
pub fn config_vrf_mup_segment_prefix(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let _segment = args.string()?; // segment list key (direct|interwork)
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            cfg.mobile_uplane.interwork_prefix = Some(IpNet::from_str(&raw).ok()?);
        }
        ConfigOp::Delete => cfg.mobile_uplane.interwork_prefix = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr>` — list-key handler.
pub fn config_vrf_neighbor(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            cfg.neighbors.entry(addr).or_default();
        }
        ConfigOp::Delete => {
            cfg.neighbors.remove(&addr);
        }
        _ => {}
    }
    Some(())
}

/// Borrow a staged neighbor without allowing trailing Delete callbacks to
/// resurrect a list entry already removed by [`config_vrf_neighbor`]. Set
/// callbacks may still arrive before the list-key callback, so they retain
/// lazy creation.
fn neighbor_entry(
    cfg: &mut BgpVrfConfig,
    address: IpAddr,
    op: ConfigOp,
) -> Option<&mut BgpVrfNeighborConfig> {
    match op {
        ConfigOp::Set => Some(cfg.neighbors.entry(address).or_default()),
        ConfigOp::Delete => cfg.neighbors.get_mut(&address),
        _ => None,
    }
}

/// `set router bgp vrf <NAME> neighbor <addr> remote-as <ASN>`.
pub fn config_vrf_neighbor_remote_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.remote_as = Some(args.u32()?),
        ConfigOp::Delete => nbr.remote_as = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> peer-group <GROUP>`.
pub fn config_vrf_neighbor_peer_group(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.peer_group = Some(args.string()?),
        ConfigOp::Delete => nbr.peer_group = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> description <STRING>`.
pub fn config_vrf_neighbor_description(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.description = Some(args.string()?),
        ConfigOp::Delete => nbr.description = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> timers connect-retry-time
/// <SECS>`.
///
/// The three `timers` callbacks stage onto
/// [`BgpVrfNeighborConfig::timer`], which `materialize_peers` copies
/// onto the peer at build time. Unlike the global neighbor's
/// equivalents (`timer::config::*`) they do **not** re-arm anything:
/// there is no live peer to reach from here — the CE peers live in the
/// per-VRF task — so a change lands when the VRF next respawns or the
/// session is cleared. That matches how every other per-VRF neighbor
/// knob (remote-as, afi-safi) already behaves.
pub fn config_vrf_neighbor_connect_retry_time(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.timer.connect_retry_time = Some(args.u16()?),
        ConfigOp::Delete => nbr.timer.connect_retry_time = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> timers hold-time <SECS>`.
pub fn config_vrf_neighbor_hold_time(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.timer.hold_time = Some(args.u16()?),
        ConfigOp::Delete => nbr.timer.hold_time = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> timers idle-hold-time
/// <SECS>`.
pub fn config_vrf_neighbor_idle_hold_time(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.timer.idle_hold_time = Some(args.u16()?),
        ConfigOp::Delete => nbr.timer.idle_hold_time = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> afi-safi {ipv4|ipv6} enabled
/// <BOOL>` — per-family activation for a CE peer, mirroring the global
/// neighbor's `config_afi_safi`. Records the verbatim statement into the
/// staged [`BgpVrfNeighborConfig::mp_explicit`]; `materialize_peers`
/// resolves the effective family set (address-derived default layered
/// with these overrides) when it builds the peer. The capability set is
/// fixed at OPEN time, so a real effective-family change drives the
/// structural commit diff and re-materializes the affected VRF task. A
/// representation-only change (for example implicit IPv4 to explicit
/// `ipv4 enabled true`) compares equal and does not reset the session.
pub fn config_vrf_neighbor_afi_safi_enabled(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => {
            let enabled = args.boolean()?;
            nbr.mp_explicit.insert(afi_safi, enabled);
        }
        ConfigOp::Delete => {
            nbr.mp_explicit.remove(&afi_safi);
        }
        _ => {}
    }
    Some(())
}

/// Common callback for
/// `router bgp vrf <NAME> neighbor <addr> afi-safi <afi> prefix-set {in,out}`.
/// Staging is diff-gated so a repeated value is a no-op even if this helper is
/// called outside the config manager's normal text-diff commit path. Changes
/// for a live VRF are coalesced and delivered at `CommitEnd`; a not-yet-running
/// VRF uses the staged value when its peers materialize.
fn config_vrf_neighbor_afi_safi_prefix_set(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
    direction: InOut,
) -> Option<()> {
    let vrf = args.string()?;
    let address = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let name = match op {
        ConfigOp::Set => Some(args.string()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };

    let changed = {
        let cfg = vrf_entry(bgp, vrf.clone(), op)?;
        update_neighbor_prefix_set(cfg, address, afi_safi, direction, name.clone(), op)
    };

    if let Some(before) = changed {
        record_pending_prefix_set_change(
            &mut bgp.vrf_prefix_set_pending,
            PendingVrfPrefixSetChange {
                vrf,
                address,
                afi_safi,
                direction,
                before,
            },
        );
    }
    Some(())
}

fn record_pending_prefix_set_change(
    pending: &mut Vec<PendingVrfPrefixSetChange>,
    change: PendingVrfPrefixSetChange,
) {
    if !pending.iter().any(|existing| {
        existing.vrf == change.vrf
            && existing.address == change.address
            && existing.afi_safi == change.afi_safi
            && existing.direction == change.direction
    }) {
        pending.push(change);
    }
}

/// Update one staged binding and return its previous value when it changed.
/// Delete callbacks must only traverse existing containers: after the parent
/// neighbor list callback removes an entry, subsequently delivered child
/// deletes must not recreate that neighbor (or its AFI container).
fn update_neighbor_prefix_set(
    cfg: &mut BgpVrfConfig,
    address: IpAddr,
    afi_safi: AfiSafi,
    direction: InOut,
    name: Option<String>,
    op: ConfigOp,
) -> Option<Option<String>> {
    let prefix_set = match op {
        ConfigOp::Set => cfg
            .neighbors
            .entry(address)
            .or_default()
            .prefix_set
            .entry(afi_safi)
            .or_default(),
        ConfigOp::Delete => cfg
            .neighbors
            .get_mut(&address)?
            .prefix_set
            .get_mut(&afi_safi)?,
        _ => return None,
    };
    let slot = prefix_set.get_mut(direction);
    if *slot == name {
        None
    } else {
        let before = slot.clone();
        *slot = name;
        Some(before)
    }
}

fn take_prefix_set_commit_changes(
    vrfs: &BTreeMap<String, BgpVrfConfig>,
    pending: &mut Vec<PendingVrfPrefixSetChange>,
) -> Vec<VrfPrefixSetChange> {
    std::mem::take(pending)
        .into_iter()
        .filter_map(|change| {
            let name = vrfs
                .get(&change.vrf)
                .and_then(|cfg| cfg.neighbors.get(&change.address))
                .and_then(|neighbor| neighbor.prefix_set.get(&change.afi_safi))
                .and_then(|prefix_set| prefix_set.get(change.direction).clone());
            (name != change.before).then_some(VrfPrefixSetChange {
                vrf: change.vrf,
                address: change.address,
                afi_safi: change.afi_safi,
                direction: change.direction,
                name,
            })
        })
        .collect()
}

/// Publish coalesced per-VRF prefix-set binding changes at the transaction
/// boundary.  In particular, a Delete+Set replacement becomes one message
/// carrying the new name; live peers never run temporarily without a filter.
pub(crate) fn apply_prefix_set_commit_changes(bgp: &mut Bgp, generation: u64) {
    let changes = take_prefix_set_commit_changes(&bgp.vrfs, &mut bgp.vrf_prefix_set_pending);
    for change in changes {
        if let Some(handle) = bgp.vrf_registry.get(&change.vrf) {
            let _ = handle.inbox.send(BgpVrfMsg::PrefixSetConfig {
                address: change.address,
                afi_safi: change.afi_safi,
                direction: change.direction,
                name: change.name,
                generation,
            });
        }
    }
    // One FIFO marker per live VRF, after every binding message above.  A
    // policy commit emits its watch batch before ConfigManager releases BGP's
    // CommitEnd barrier, so this closes the same transaction on both actors.
    for handle in bgp.vrf_registry.values() {
        let _ = handle
            .inbox
            .send(BgpVrfMsg::PrefixSetCommitEnd { generation });
    }
}

pub fn config_vrf_neighbor_afi_safi_prefix_set_in(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_vrf_neighbor_afi_safi_prefix_set(bgp, args, op, InOut::Input)
}

pub fn config_vrf_neighbor_afi_safi_prefix_set_out(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_vrf_neighbor_afi_safi_prefix_set(bgp, args, op, InOut::Output)
}

/// `set router bgp vrf <NAME> afi-safi ipv4` — presence container.
pub fn config_vrf_afi_ipv4(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            vrf_entry(bgp, name, op)?
                .ipv4_unicast
                .get_or_insert_with(Default::default);
        }
        ConfigOp::Delete => {
            // Dropping the whole `afi-safi ipv4` container collapses to
            // this container delete — the per-network deletes are not
            // re-emitted — so withdraw every self-originated network
            // from the running VRF before clearing, else the routes
            // outlive the config. Idempotent with
            // `config_vrf_afi_ipv4_network`: a repeat WithdrawNetwork
            // on an already-gone prefix is a no-op in the VRF task.
            let nets: Vec<Ipv4Net> = bgp
                .vrfs
                .get(&name)
                .and_then(|c| c.ipv4_unicast.as_ref())
                .map(|af| af.networks.iter().copied().collect())
                .unwrap_or_default();
            if let Some(handle) = bgp.vrf_registry.get(&name) {
                for prefix in nets {
                    let _ = handle.inbox.send(BgpVrfMsg::WithdrawNetwork { prefix });
                }
            }
            if let Some(cfg) = vrf_entry(bgp, name, op) {
                cfg.ipv4_unicast = None;
            }
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv4 network <PREFIX>`.
pub fn config_vrf_afi_ipv4_network(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let prefix = args.v4net()?;
    let set = match op {
        ConfigOp::Set => true,
        ConfigOp::Delete => false,
        _ => return Some(()),
    };
    {
        let af = vrf_entry(bgp, name.clone(), op)?
            .ipv4_unicast
            .get_or_insert_with(Default::default);
        if set {
            af.networks.insert(prefix);
        } else {
            af.networks.remove(&prefix);
        }
    }
    // `compute_vrf_diff` only spawns / despawns on the VRF *name*
    // set, so a `network` add/remove on an already-running VRF
    // reaches the task only through a message — drive the
    // originate / withdraw on the live instance. When the VRF isn't
    // spawned yet (initial config), the spawn-time materialize reads
    // the same `networks` set, so the message is simply skipped.
    if let Some(handle) = bgp.vrf_registry.get(&name) {
        let msg = if set {
            BgpVrfMsg::OriginateNetwork { prefix }
        } else {
            BgpVrfMsg::WithdrawNetwork { prefix }
        };
        let _ = handle.inbox.send(msg);
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv6` — presence container.
pub fn config_vrf_afi_ipv6(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            vrf_entry(bgp, name, op)?
                .ipv6_unicast
                .get_or_insert_with(Default::default);
        }
        ConfigOp::Delete => {
            // See `config_vrf_afi_ipv4`: withdraw every self-originated
            // network from the running VRF before dropping the
            // container, since the container delete is all the diff
            // emits when the whole `afi-safi ipv6` block is removed.
            let nets: Vec<Ipv6Net> = bgp
                .vrfs
                .get(&name)
                .and_then(|c| c.ipv6_unicast.as_ref())
                .map(|af| af.networks.iter().copied().collect())
                .unwrap_or_default();
            if let Some(handle) = bgp.vrf_registry.get(&name) {
                for prefix in nets {
                    let _ = handle.inbox.send(BgpVrfMsg::WithdrawNetworkV6 { prefix });
                }
            }
            if let Some(cfg) = vrf_entry(bgp, name, op) {
                cfg.ipv6_unicast = None;
            }
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv6 network <PREFIX>`.
pub fn config_vrf_afi_ipv6_network(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let prefix = args.v6net()?;
    let set = match op {
        ConfigOp::Set => true,
        ConfigOp::Delete => false,
        _ => return Some(()),
    };
    {
        let af = vrf_entry(bgp, name.clone(), op)?
            .ipv6_unicast
            .get_or_insert_with(Default::default);
        if set {
            af.networks.insert(prefix);
        } else {
            af.networks.remove(&prefix);
        }
    }
    // See `config_vrf_afi_ipv4_network`: drive the originate /
    // withdraw on the running VRF task, since `compute_vrf_diff`
    // never re-spawns it for a network-only change.
    if let Some(handle) = bgp.vrf_registry.get(&name) {
        let msg = if set {
            BgpVrfMsg::OriginateNetworkV6 { prefix }
        } else {
            BgpVrfMsg::WithdrawNetworkV6 { prefix }
        };
        let _ = handle.inbox.send(msg);
    }
    Some(())
}

/// Enable/disable one redistribute source for a VRF/AFI in the staged
/// config, and drive the change onto the running VRF task. Shared by
/// the four `redistribute {connected,static}` callbacks. Mirrors the
/// `network` callbacks: `compute_vrf_diff` only re-spawns on the VRF
/// *name* set, so a redistribute-only change reaches a live task through
/// a [`BgpVrfMsg`]; an initial-config VRF picks it up at spawn-time
/// materialization, which reads the same `redistribute` set.
fn vrf_redist_set(
    bgp: &mut Bgp,
    name: String,
    afi: RedistAfi,
    source: BgpRedistSource,
    op: ConfigOp,
) -> Option<()> {
    let set = match op {
        ConfigOp::Set => true,
        ConfigOp::Delete => false,
        _ => return Some(()),
    };
    {
        let Some(cfg) = vrf_entry(bgp, name.clone(), op) else {
            return Some(());
        };
        let redist = match afi {
            RedistAfi::Ipv4 => {
                &mut cfg
                    .ipv4_unicast
                    .get_or_insert_with(Default::default)
                    .redistribute
            }
            RedistAfi::Ipv6 => {
                &mut cfg
                    .ipv6_unicast
                    .get_or_insert_with(Default::default)
                    .redistribute
            }
        };
        if set {
            redist.insert(source);
        } else {
            redist.remove(&source);
        }
    }
    if let Some(handle) = bgp.vrf_registry.get(&name) {
        let msg = if set {
            BgpVrfMsg::RedistEnable { afi, source }
        } else {
            BgpVrfMsg::RedistDisable { afi, source }
        };
        let _ = handle.inbox.send(msg);
    }
    Some(())
}

/// Clear every redistribute source for a VRF/AFI and withdraw them
/// from the running task. Driven by the `redistribute` container
/// delete, whose child source-deletes the diff does not re-emit (same
/// rationale as `config_vrf_afi_ipv4`'s network sweep).
fn vrf_redist_clear(bgp: &mut Bgp, name: String, afi: RedistAfi) {
    let sources: Vec<BgpRedistSource> = {
        // Delete-only path: never create the entry (see `vrf_entry`).
        let Some(cfg) = bgp.vrfs.get_mut(&name) else {
            return;
        };
        let redist = match afi {
            RedistAfi::Ipv4 => cfg.ipv4_unicast.as_mut().map(|af| &mut af.redistribute),
            RedistAfi::Ipv6 => cfg.ipv6_unicast.as_mut().map(|af| &mut af.redistribute),
        };
        match redist {
            Some(set) => {
                let drained: Vec<_> = set.iter().copied().collect();
                set.clear();
                drained
            }
            None => Vec::new(),
        }
    };
    if let Some(handle) = bgp.vrf_registry.get(&name) {
        for source in sources {
            let _ = handle.inbox.send(BgpVrfMsg::RedistDisable { afi, source });
        }
    }
}

/// `delete router bgp vrf <NAME> afi-safi ipv4 redistribute` — clear
/// all IPv4 redistribute sources. The set callback for the bare
/// container is a no-op (sources are enabled by their own leaves).
pub fn config_vrf_afi_ipv4_redistribute(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if matches!(op, ConfigOp::Delete) {
        vrf_redist_clear(bgp, name, RedistAfi::Ipv4);
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv4 redistribute connected`.
pub fn config_vrf_afi_ipv4_redistribute_connected(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv4, BgpRedistSource::Connected, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv4 redistribute static`.
pub fn config_vrf_afi_ipv4_redistribute_static(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv4, BgpRedistSource::Static, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv4 redistribute ospf`.
pub fn config_vrf_afi_ipv4_redistribute_ospf(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv4, BgpRedistSource::Ospf, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv4 redistribute isis`.
pub fn config_vrf_afi_ipv4_redistribute_isis(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv4, BgpRedistSource::Isis, op)
}

/// `delete router bgp vrf <NAME> afi-safi ipv6 redistribute`.
pub fn config_vrf_afi_ipv6_redistribute(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if matches!(op, ConfigOp::Delete) {
        vrf_redist_clear(bgp, name, RedistAfi::Ipv6);
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv6 redistribute connected`.
pub fn config_vrf_afi_ipv6_redistribute_connected(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv6, BgpRedistSource::Connected, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv6 redistribute static`.
pub fn config_vrf_afi_ipv6_redistribute_static(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv6, BgpRedistSource::Static, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv6 redistribute ospf`.
pub fn config_vrf_afi_ipv6_redistribute_ospf(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv6, BgpRedistSource::Ospf, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv6 redistribute isis`.
pub fn config_vrf_afi_ipv6_redistribute_isis(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv6, BgpRedistSource::Isis, op)
}

/// `set router bgp vrf <NAME> evpn advertise-ipv4 <bool>`.
pub fn config_vrf_evpn_advertise_ipv4(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.evpn_advertise_v4 = args.boolean()?,
        ConfigOp::Delete => cfg.evpn_advertise_v4 = false,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> evpn advertise-ipv6 <bool>`.
pub fn config_vrf_evpn_advertise_ipv6(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.evpn_advertise_v6 = args.boolean()?,
        ConfigOp::Delete => cfg.evpn_advertise_v6 = false,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> evpn l3vni <VNI>`.
pub fn config_vrf_evpn_l3vni(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.l3vni = Some(args.u32()?),
        ConfigOp::Delete => cfg.l3vni = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> evpn router-mac <MAC>` (symmetric IRB).
pub fn config_vrf_evpn_router_mac(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let mac: crate::rib::MacAddr = args.string()?.parse().ok()?;
            cfg.router_mac = Some(mac.octets());
        }
        ConfigOp::Delete => cfg.router_mac = None,
        _ => {}
    }
    Some(())
}

/// Commit-time observation hook. Emits a single `debug!` line per
/// VRF entry so operators can see the staged intent at the boundary
/// where spawn / despawn logic consumes `Bgp::vrfs`.
pub fn log_commit_diff(bgp: &Bgp) {
    if bgp.vrfs.is_empty() {
        return;
    }
    for (name, cfg) in &bgp.vrfs {
        bgp_vrf_trace!(
            bgp.tracing,
            vrf = %name,
            rd = ?cfg.rd,
            router_id = ?cfg.router_id,
            label_mode = ?cfg.label_mode,
            neighbors = cfg.neighbors.len(),
            ipv4_unicast = cfg.ipv4_unicast.is_some(),
            ipv6_unicast = cfg.ipv6_unicast.is_some(),
            evpn_advertise_v4 = cfg.evpn_advertise_v4,
            evpn_advertise_v6 = cfg.evpn_advertise_v6,
            "bgp: per-VRF intent staged",
        );
    }
}

#[cfg(test)]
mod tests {
    //! Pure-data tests on `BgpVrfConfig`. Building a full `Bgp`
    //! instance is impractical (it owns netlink-bound state and
    //! channels), so these tests exercise the callback bodies via
    //! a small helper that mutates a `BTreeMap<String, BgpVrfConfig>`
    //! directly. The callbacks themselves are thin wrappers over the
    //! same map mutations, so the test coverage of the staging
    //! shape is faithful to production behaviour.
    use super::*;

    fn neighbor_or_default(cfg: &mut BgpVrfConfig, addr: IpAddr) -> &mut BgpVrfNeighborConfig {
        cfg.neighbors.entry(addr).or_default()
    }

    fn stage_prefix_set(
        vrfs: &mut BTreeMap<String, BgpVrfConfig>,
        pending: &mut Vec<PendingVrfPrefixSetChange>,
        address: IpAddr,
        name: Option<&str>,
        op: ConfigOp,
    ) {
        let cfg = vrfs.get_mut("blue").unwrap();
        if let Some(before) = update_neighbor_prefix_set(
            cfg,
            address,
            AfiSafi::new(Afi::Ip, Safi::Unicast),
            InOut::Output,
            name.map(str::to_string),
            op,
        ) {
            record_pending_prefix_set_change(
                pending,
                PendingVrfPrefixSetChange {
                    vrf: "blue".to_string(),
                    address,
                    afi_safi: AfiSafi::new(Afi::Ip, Safi::Unicast),
                    direction: InOut::Output,
                    before,
                },
            );
        }
    }

    #[test]
    fn label_mode_parse_accepts_yang_enums() {
        assert_eq!(
            BgpVrfLabelMode::parse("per-vrf"),
            Some(BgpVrfLabelMode::Vrf)
        );
        assert_eq!(
            BgpVrfLabelMode::parse("per-route"),
            Some(BgpVrfLabelMode::Route)
        );
        assert_eq!(
            BgpVrfLabelMode::parse("per-nexthop"),
            Some(BgpVrfLabelMode::Nexthop)
        );
        assert_eq!(BgpVrfLabelMode::parse("bogus"), None);
    }

    #[test]
    fn encapsulation_parse_accepts_yang_enums() {
        assert_eq!(
            BgpVrfEncapsulation::parse("mpls"),
            Some(BgpVrfEncapsulation::Mpls)
        );
        assert_eq!(
            BgpVrfEncapsulation::parse("srv6"),
            Some(BgpVrfEncapsulation::Srv6)
        );
        assert_eq!(BgpVrfEncapsulation::parse("bogus"), None);
    }

    #[test]
    fn vrf_config_default_encapsulation_is_mpls() {
        // YANG default is `mpls` — a VRF with no `encapsulation` leaf
        // keeps the RFC 4364 MPLS service-label data path.
        assert_eq!(
            BgpVrfConfig::default().encapsulation,
            BgpVrfEncapsulation::Mpls
        );
    }

    #[test]
    fn barrier_rollback_makes_identical_prefix_set_retry_publish_once() {
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let mut vrfs = BTreeMap::from([("blue".to_string(), BgpVrfConfig::default())]);
        let mut pending = Vec::new();

        // Committed/runtime value before the rejected transaction.
        stage_prefix_set(&mut vrfs, &mut pending, address, Some("OLD"), ConfigOp::Set);
        pending.clear();

        // Candidate OLD -> DENY was delivered, but policy ACK failed before
        // BGP CommitEnd.  The manager replays the inverse in reverse order.
        stage_prefix_set(&mut vrfs, &mut pending, address, None, ConfigOp::Delete);
        stage_prefix_set(
            &mut vrfs,
            &mut pending,
            address,
            Some("DENY"),
            ConfigOp::Set,
        );
        stage_prefix_set(&mut vrfs, &mut pending, address, None, ConfigOp::Delete);
        stage_prefix_set(&mut vrfs, &mut pending, address, Some("OLD"), ConfigOp::Set);

        // The inverse CommitEnd closes the rollback generation.  Its net
        // binding diff is empty, so the live task receives no policy change;
        // the following CommitStart only captures this restored baseline.
        assert!(take_prefix_set_commit_changes(&vrfs, &mut pending).is_empty());
        assert_eq!(
            vrfs["blue"].neighbors[&address].prefix_set[&AfiSafi::new(Afi::Ip, Safi::Unicast)]
                .output
                .as_deref(),
            Some("OLD")
        );

        // Identical candidate retry must not collapse to a callback no-op.
        stage_prefix_set(&mut vrfs, &mut pending, address, None, ConfigOp::Delete);
        stage_prefix_set(
            &mut vrfs,
            &mut pending,
            address,
            Some("DENY"),
            ConfigOp::Set,
        );
        let published = take_prefix_set_commit_changes(&vrfs, &mut pending);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].name.as_deref(), Some("DENY"));
        assert!(take_prefix_set_commit_changes(&vrfs, &mut pending).is_empty());
    }

    #[test]
    fn mobile_uplane_default_is_empty() {
        let mup = BgpVrfConfig::default().mobile_uplane;
        assert!(mup.routes.is_empty());
    }

    #[test]
    fn mobile_uplane_binds_both_directions() {
        // One VRF may bind both st1 and st2 (single-N6 UPF, issue #1947):
        // each direction is an independent map entry, and removing one
        // leaves the other intact.
        let mut cfg = BgpVrfConfig::default();
        cfg.mobile_uplane.routes.insert(
            MupSrv6Direction::Decapsulation,
            MupRouteBinding {
                network_instance: Some("internet".to_string()),
                mup_ext_comm: Some("1:2".parse().unwrap()),
            },
        );
        cfg.mobile_uplane.routes.insert(
            MupSrv6Direction::Encapsulation,
            MupRouteBinding {
                network_instance: Some("internet".to_string()),
                mup_ext_comm: None,
            },
        );
        assert_eq!(cfg.mobile_uplane.routes.len(), 2);
        let st2 = &cfg.mobile_uplane.routes[&MupSrv6Direction::Decapsulation];
        assert_eq!(st2.network_instance.as_deref(), Some("internet"));
        assert_eq!(st2.mup_ext_comm, Some("1:2".parse().unwrap()));

        cfg.mobile_uplane
            .routes
            .remove(&MupSrv6Direction::Decapsulation);
        assert!(
            cfg.mobile_uplane
                .routes
                .contains_key(&MupSrv6Direction::Encapsulation),
            "removing st2 leaves the st1 binding intact"
        );
    }

    #[test]
    fn neighbor_default_is_empty() {
        // A `set ... neighbor X` with no further leaves stages an empty
        // neighbor: no remote-as / peer-group / description and no
        // explicit afi-safi activation. The peer only materializes once
        // a remote-as (own or group-inherited) is known.
        let nbr = BgpVrfNeighborConfig::default();
        assert!(nbr.remote_as.is_none());
        assert!(nbr.peer_group.is_none());
        assert!(nbr.description.is_none());
        assert!(nbr.mp_explicit.is_empty());
        // Every timer leaf unset — `materialize_peers` copies this
        // wholesale onto the peer, so an all-`None` default is what keeps
        // a `timers`-less VRF neighbor on the stock cadence.
        assert!(nbr.timer.connect_retry_time.is_none());
        assert!(nbr.timer.hold_time.is_none());
        assert!(nbr.timer.idle_hold_time.is_none());
        assert!(nbr.prefix_set.is_empty());
    }

    #[test]
    fn neighbor_timers_stage_and_clear_independently() {
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let mut cfg = BgpVrfConfig::default();

        let nbr = neighbor_entry(&mut cfg, address, ConfigOp::Set).unwrap();
        nbr.timer.connect_retry_time = Some(3);
        nbr.timer.hold_time = Some(9);
        nbr.timer.idle_hold_time = Some(1);

        let nbr = &cfg.neighbors[&address];
        assert_eq!(nbr.timer.connect_retry_time, Some(3));
        assert_eq!(nbr.timer.hold_time, Some(9));
        assert_eq!(nbr.timer.idle_hold_time, Some(1));

        // Clearing one leaf must leave the siblings alone: the three
        // callbacks share one staged `timer::Config`, so a careless
        // implementation could reset the struct instead of the field.
        cfg.neighbors.get_mut(&address).unwrap().timer.hold_time = None;
        let nbr = &cfg.neighbors[&address];
        assert!(nbr.timer.hold_time.is_none());
        assert_eq!(nbr.timer.connect_retry_time, Some(3));
        assert_eq!(nbr.timer.idle_hold_time, Some(1));
    }

    #[test]
    fn neighbor_timers_leave_the_inert_leaves_unset() {
        // The schema deliberately omits advertisement-interval /
        // originate-interval / delay-open-time: they are staged onto
        // `PeerConfig::timer` and never read by any arming path, even for
        // a global neighbor. Sharing `timer::Config` with the peer means
        // they exist as fields, so pin that they stay `None` — if one is
        // ever wired up, this test should fail and prompt exposing it
        // here too.
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let mut cfg = BgpVrfConfig::default();
        let nbr = neighbor_entry(&mut cfg, address, ConfigOp::Set).unwrap();
        nbr.timer.connect_retry_time = Some(3);

        assert!(nbr.timer.min_adv_interval.is_none());
        assert!(nbr.timer.orig_interval.is_none());
        assert!(nbr.timer.delay_open_time.is_none());
    }

    #[test]
    fn neighbor_prefix_sets_are_scoped_by_family_and_direction() {
        use bgp_packet::{Afi, Safi};

        let mut nbr = BgpVrfNeighborConfig::default();
        let ipv4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let ipv6 = AfiSafi::new(Afi::Ip6, Safi::Unicast);

        nbr.prefix_set.entry(ipv4).or_default().input = Some("PEER-IN-V4".to_string());
        nbr.prefix_set.entry(ipv4).or_default().output = Some("PEER-OUT-V4".to_string());
        nbr.prefix_set.entry(ipv6).or_default().input = Some("PEER-IN-V6".to_string());

        let v4 = nbr.prefix_set.get(&ipv4).unwrap();
        assert_eq!(v4.input.as_deref(), Some("PEER-IN-V4"));
        assert_eq!(v4.output.as_deref(), Some("PEER-OUT-V4"));
        let v6 = nbr.prefix_set.get(&ipv6).unwrap();
        assert_eq!(v6.input.as_deref(), Some("PEER-IN-V6"));
        assert!(v6.output.is_none());

        nbr.prefix_set.get_mut(&ipv4).unwrap().input = None;
        assert!(nbr.prefix_set.get(&ipv4).unwrap().input.is_none());
        assert_eq!(
            nbr.prefix_set.get(&ipv4).unwrap().output.as_deref(),
            Some("PEER-OUT-V4")
        );
        assert_eq!(
            nbr.prefix_set.get(&ipv6).unwrap().input.as_deref(),
            Some("PEER-IN-V6")
        );
    }

    #[test]
    fn prefix_set_replacement_is_coalesced_to_final_name_at_commit() {
        use bgp_packet::{Afi, Safi};

        let vrf = "blue".to_string();
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let afi_safi = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let mut vrfs = BTreeMap::new();
        let mut cfg = BgpVrfConfig::default();
        cfg.neighbors
            .entry(address)
            .or_default()
            .prefix_set
            .entry(afi_safi)
            .or_default()
            .input = Some("NEW".to_string());
        vrfs.insert(vrf.clone(), cfg);

        // A value replacement is observed as Delete(OLD), Set(NEW). Only the
        // state before the first callback is retained in the pending record.
        let mut pending = Vec::new();
        record_pending_prefix_set_change(
            &mut pending,
            PendingVrfPrefixSetChange {
                vrf: vrf.clone(),
                address,
                afi_safi,
                direction: InOut::Input,
                before: Some("OLD".to_string()),
            },
        );
        record_pending_prefix_set_change(
            &mut pending,
            PendingVrfPrefixSetChange {
                vrf: vrf.clone(),
                address,
                afi_safi,
                direction: InOut::Input,
                before: None,
            },
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].before.as_deref(), Some("OLD"));
        let changes = take_prefix_set_commit_changes(&vrfs, &mut pending);

        assert!(pending.is_empty());
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].vrf, vrf);
        assert_eq!(changes[0].name.as_deref(), Some("NEW"));
    }

    #[test]
    fn prefix_set_delete_then_restore_is_not_published() {
        use bgp_packet::{Afi, Safi};

        let vrf = "blue".to_string();
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let afi_safi = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let mut vrfs = BTreeMap::new();
        let mut cfg = BgpVrfConfig::default();
        cfg.neighbors
            .entry(address)
            .or_default()
            .prefix_set
            .entry(afi_safi)
            .or_default()
            .input = Some("SAME".to_string());
        vrfs.insert(vrf.clone(), cfg);

        let mut pending = vec![PendingVrfPrefixSetChange {
            vrf,
            address,
            afi_safi,
            direction: InOut::Input,
            before: Some("SAME".to_string()),
        }];

        assert!(take_prefix_set_commit_changes(&vrfs, &mut pending).is_empty());
        assert!(pending.is_empty());
    }

    #[test]
    fn prefix_set_child_delete_does_not_recreate_removed_neighbor() {
        use bgp_packet::{Afi, Safi};

        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let afi_safi = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let mut cfg = BgpVrfConfig::default();

        // Models callback order for deleting the whole neighbor list entry:
        // the parent callback removed it before this child-leaf delete runs.
        assert!(
            update_neighbor_prefix_set(
                &mut cfg,
                address,
                afi_safi,
                InOut::Input,
                None,
                ConfigOp::Delete,
            )
            .is_none()
        );
        assert!(cfg.neighbors.is_empty());
    }

    #[test]
    fn whole_neighbor_delete_child_callbacks_leave_no_ghost_or_dirty_diff() {
        use bgp_packet::{Afi, Safi};

        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let afi_safi = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let mut cfg = BgpVrfConfig::default();
        let neighbor = cfg.neighbors.entry(address).or_default();
        neighbor.remote_as = Some(65001);
        neighbor.peer_group = Some("CE".to_string());
        neighbor.description = Some("deleted peer".to_string());
        neighbor.mp_explicit.insert(afi_safi, true);
        neighbor.prefix_set.entry(afi_safi).or_default().input = Some("CE-IN".to_string());

        // A whole-list delete removes the parent first. Every child callback
        // may still follow, but none may lazily create the neighbor again.
        cfg.neighbors.remove(&address);
        assert!(neighbor_entry(&mut cfg, address, ConfigOp::Delete).is_none());
        assert!(neighbor_entry(&mut cfg, address, ConfigOp::Delete).is_none());
        assert!(neighbor_entry(&mut cfg, address, ConfigOp::Delete).is_none());
        assert!(neighbor_entry(&mut cfg, address, ConfigOp::Delete).is_none());
        assert!(
            update_neighbor_prefix_set(
                &mut cfg,
                address,
                afi_safi,
                InOut::Input,
                None,
                ConfigOp::Delete,
            )
            .is_none()
        );
        assert!(cfg.neighbors.is_empty());

        // The resulting staged shape is exactly a clean neighbor-free
        // runtime baseline, so the next unchanged commit has no structural
        // respawn diff caused by a default-valued ghost entry.
        let clean = BgpVrfConfig::default();
        let groups = BTreeMap::new();
        assert!(runtime_structure_eq(&clean, &groups, &cfg, &groups));
        assert!(runtime_structure_eq(&cfg, &groups, &cfg.clone(), &groups));
    }

    #[test]
    fn neighbor_child_set_can_still_create_before_list_key_callback() {
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let mut cfg = BgpVrfConfig::default();

        neighbor_entry(&mut cfg, address, ConfigOp::Set)
            .unwrap()
            .remote_as = Some(65001);

        assert_eq!(cfg.neighbors[&address].remote_as, Some(65001));
    }

    #[test]
    fn vrf_config_default_has_label_mode_per_vrf() {
        let cfg = BgpVrfConfig::default();
        assert_eq!(cfg.label_mode, BgpVrfLabelMode::Vrf);
        assert!(cfg.rd.is_none());
        assert!(cfg.router_id.is_none());
        assert!(cfg.neighbors.is_empty());
        assert!(cfg.ipv4_unicast.is_none());
        assert!(cfg.ipv6_unicast.is_none());
    }

    #[test]
    fn rd_round_trips_through_from_str() {
        let rd = RouteDistinguisher::from_str("65000:10").expect("RD parses");
        let mut cfg = BgpVrfConfig {
            rd: Some(rd),
            ..Default::default()
        };
        assert_eq!(cfg.rd, Some(rd));
        cfg.rd = None;
        assert!(cfg.rd.is_none());
    }

    #[test]
    fn neighbor_remote_as_set_and_clear() {
        let mut cfg = BgpVrfConfig::default();
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        let nbr = neighbor_or_default(&mut cfg, addr);
        nbr.remote_as = Some(65001);
        assert_eq!(
            cfg.neighbors.get(&addr).and_then(|n| n.remote_as),
            Some(65001)
        );

        let nbr = cfg.neighbors.get_mut(&addr).unwrap();
        nbr.remote_as = None;
        assert!(cfg.neighbors.get(&addr).unwrap().remote_as.is_none());
    }

    #[test]
    fn afi_v4_network_insert_and_remove() {
        let mut cfg = BgpVrfConfig::default();
        let prefix: Ipv4Net = "10.10.0.0/16".parse().unwrap();
        cfg.ipv4_unicast
            .get_or_insert_with(Default::default)
            .networks
            .insert(prefix);
        assert!(
            cfg.ipv4_unicast
                .as_ref()
                .unwrap()
                .networks
                .contains(&prefix)
        );
        cfg.ipv4_unicast.as_mut().unwrap().networks.remove(&prefix);
        assert!(cfg.ipv4_unicast.as_ref().unwrap().networks.is_empty());
    }

    #[test]
    fn afi_v6_network_insert_and_remove() {
        let mut cfg = BgpVrfConfig::default();
        let prefix: Ipv6Net = "2001:db8::/64".parse().unwrap();
        cfg.ipv6_unicast
            .get_or_insert_with(Default::default)
            .networks
            .insert(prefix);
        assert!(
            cfg.ipv6_unicast
                .as_ref()
                .unwrap()
                .networks
                .contains(&prefix)
        );
        cfg.ipv6_unicast.as_mut().unwrap().networks.remove(&prefix);
        assert!(cfg.ipv6_unicast.as_ref().unwrap().networks.is_empty());
    }
}
