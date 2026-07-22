use std::collections::{BTreeMap, HashMap};

use anyhow::{Error, Result};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};

use super::{
    AsPathSetConfig, CommunitySetConfig, ExtCommunitySetConfig, KeyChain, KeyChainScope,
    KeyChainSetConfig, LargeCommunitySetConfig, PolicyConfig, PolicyList, PrefixSet,
    PrefixSetConfig, policy_entry_sync,
};

pub type ShowCallback = fn(&Policy, Args, bool) -> Result<String, Error>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PolicyType {
    PrefixSetIn,
    PrefixSetOut,
    PolicyListIn,
    PolicyListOut,
    /// A BGP per-AFI `table-map` binding (zebra-bgp-table-map.yang).
    /// Rides the same policy-list watch registry as
    /// `PolicyListIn`/`Out`, but `ident` encodes the AFI/SAFI rather
    /// than a peer index. Like the policy-lists it shares the registry
    /// with, `Register` always answers — even with `policy_list: None`
    /// — because an unresolved table-map is deny-all (FRR parity) and
    /// the subscriber needs the definitive answer to resync its FIB
    /// installs exactly once.
    TableMap,
    /// Subscription to a named `/key-chains/key-chain <name>`. The
    /// inner `KeyChainScope` lets the subscribed protocol
    /// demultiplex updates back to the right per-link / per-neighbor
    /// / per-IS-IS-scope container when its `process_policy_msg`
    /// handler fires. See `policy::keychain` for the registry.
    KeyChain(KeyChainScope),
}

#[derive(Debug)]
pub enum Message {
    Subscribe {
        proto: String,
        tx: UnboundedSender<PolicyRx>,
    },
    /// Drop a protocol client and every watch it registered. Per-VRF BGP
    /// tasks use a distinct protocol name and can be respawned frequently;
    /// without whole-client cleanup, stale watches can target a new task
    /// whose local peer indexes happen to be reused.
    Unsubscribe { proto: String },
    Register {
        proto: String,
        name: String,
        ident: usize,
        policy_type: PolicyType,
    },
    /// Counterpart of `Register`. Sent by a protocol when a peer
    /// detaches a policy (operator runs `delete policy in X`,
    /// or rebinds to a different name). Without this the watcher
    /// list grows unbounded as peers churn or rename their policy
    /// references.
    Unregister {
        proto: String,
        name: String,
        ident: usize,
        policy_type: PolicyType,
    },
}

// Message from rib to protocol module.
#[derive(Debug, PartialEq)]
pub enum PolicyRx {
    /// Start of one policy commit's prefix-set notification batch.  Direct
    /// watch updates following this message must not be applied by per-VRF
    /// BGP until its own CommitEnd marker arrives: the same transaction may
    /// rebind that watch to another name.
    PrefixSetCommitStart { generation: u64 },
    /// Canonical prefix-set inventory after one policy CommitEnd.  Per-VRF
    /// BGP uses this to distinguish a known replacement (atomic object swap)
    /// from an unknown replacement (immediate fail-close) without waiting
    /// for an asynchronous per-watch resolve reply.
    PrefixSetInventory {
        generation: u64,
        prefix_sets: BTreeMap<String, PrefixSet>,
    },
    PrefixSet {
        /// Prefix-set registry generation from which this object was
        /// resolved.  Register replies are tagged as well as commit-driven
        /// watch updates: otherwise a Register processed after the policy
        /// actor has advanced can expose the next commit before the
        /// subscribing protocol receives its matching CommitEnd.
        generation: u64,
        name: String,
        ident: usize,
        policy_type: PolicyType,
        prefix_set: Option<PrefixSet>,
    },
    PolicyList {
        name: String,
        ident: usize,
        policy_type: PolicyType,
        policy_list: Option<PolicyList>,
    },
    /// A `/key-chains/key-chain <name>` was added, edited, or
    /// removed. `key_chain == None` means remove. `policy_type`
    /// always carries `PolicyType::KeyChain(scope)` so the receiver
    /// can route the update to the right per-subsystem container.
    KeyChain {
        name: String,
        ident: usize,
        policy_type: PolicyType,
        key_chain: Option<KeyChain>,
    },
}

pub struct PolicyRxChannel {
    pub tx: UnboundedSender<PolicyRx>,
    pub rx: UnboundedReceiver<PolicyRx>,
}

impl PolicyRxChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

/// Notifications a per-set commit path fires when an entry changes.
///
/// Each commit phase (prefix-set, policy-list, key-chain, ...)
/// constructs a syncer scoped to its own watch map and calls only
/// the relevant subset of methods. Default no-op bodies let a syncer
/// implement just the methods it needs without re-declaring the
/// others — keeps PolicySyncer / KeyChainSyncer focused.
pub trait Syncer {
    fn prefix_set_update(&self, _name: &str, _prefix_set: &PrefixSet) {}
    fn prefix_set_remove(&self, _name: &str) {}
    fn policy_list_update(&self, _name: &str, _policy_list: &PolicyList) {}
    fn policy_list_remove(&self, _name: &str) {}
    fn key_chain_update(&self, _name: &str, _key_chain: &KeyChain) {}
    fn key_chain_remove(&self, _name: &str) {}
}

pub struct PolicySyncer<'a> {
    watch_map: &'a BTreeMap<String, Vec<PolicyWatch>>,
    clients: &'a BTreeMap<String, UnboundedSender<PolicyRx>>,
    generation: u64,
}

/// `Syncer` used by the key-chain commit path. Unlike prefix-set /
/// policy-list, key-chain watchers can come from multiple distinct
/// `KeyChainScope`s (per-OSPF-link, per-BGP-neighbor, ...). The
/// `policy_type` carried on each `PolicyWatch` already encodes the
/// scope, so we just thread it through unchanged.
pub struct KeyChainSyncer<'a> {
    watch_map: &'a BTreeMap<String, Vec<PolicyWatch>>,
    clients: &'a BTreeMap<String, UnboundedSender<PolicyRx>>,
}

impl<'a> Syncer for PolicySyncer<'a> {
    fn prefix_set_update(&self, name: &str, prefix_set: &PrefixSet) {
        // Notify all watchers of this prefix-set update
        if let Some(watches) = self.watch_map.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PrefixSet {
                        generation: self.generation,
                        name: name.to_string(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        prefix_set: Some(prefix_set.clone()),
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }

    fn prefix_set_remove(&self, name: &str) {
        if let Some(watches) = self.watch_map.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PrefixSet {
                        generation: self.generation,
                        name: name.to_string(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        prefix_set: None,
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }

    fn policy_list_update(&self, name: &str, policy_list: &PolicyList) {
        if let Some(watches) = self.watch_map.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PolicyList {
                        name: name.to_string(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        policy_list: Some(policy_list.clone()),
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }

    fn policy_list_remove(&self, name: &str) {
        if let Some(watches) = self.watch_map.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PolicyList {
                        name: name.to_string(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        policy_list: None,
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }
}

impl<'a> Syncer for KeyChainSyncer<'a> {
    fn key_chain_update(&self, name: &str, key_chain: &KeyChain) {
        if let Some(watches) = self.watch_map.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::KeyChain {
                        name: name.to_string(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        key_chain: Some(key_chain.clone()),
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }

    fn key_chain_remove(&self, name: &str) {
        if let Some(watches) = self.watch_map.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::KeyChain {
                        name: name.to_string(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        key_chain: None,
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }
}

pub struct Policy {
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub policy_config: PolicyConfig,
    pub prefix_config: PrefixSetConfig,
    pub community_config: CommunitySetConfig,
    pub ext_community_config: ExtCommunitySetConfig,
    pub large_community_config: LargeCommunitySetConfig,
    pub as_path_config: AsPathSetConfig,
    /// Canonical RFC 8177 key-chain registry. Protocol modules
    /// (OSPF, IS-IS, BGP) subscribe to it via the policy actor
    /// rather than maintaining their own copy.
    pub key_chain_config: KeyChainSetConfig,
    pub clients: BTreeMap<String, UnboundedSender<PolicyRx>>,
    pub watch_prefix: BTreeMap<String, Vec<PolicyWatch>>,
    pub watch_policy: BTreeMap<String, Vec<PolicyWatch>>,
    pub watch_keychain: BTreeMap<String, Vec<PolicyWatch>>,
    prefix_set_generation: u64,
}

#[derive(Debug)]
pub struct PolicyWatch {
    pub proto: String,
    pub ident: usize,
    pub policy_type: PolicyType,
}

impl Policy {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut policy = Self {
            tx,
            rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            policy_config: PolicyConfig::new(),
            prefix_config: PrefixSetConfig::new(),
            community_config: CommunitySetConfig::new(),
            ext_community_config: ExtCommunitySetConfig::new(),
            large_community_config: LargeCommunitySetConfig::new(),
            as_path_config: AsPathSetConfig::new(),
            key_chain_config: KeyChainSetConfig::new(),
            clients: BTreeMap::new(),
            watch_prefix: BTreeMap::new(),
            watch_policy: BTreeMap::new(),
            watch_keychain: BTreeMap::new(),
            prefix_set_generation: 0,
        };
        policy.show_build();
        policy
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Subscribe { proto, tx } => {
                if proto.starts_with("bgp:vrf:") {
                    let _ = tx.send(PolicyRx::PrefixSetInventory {
                        generation: self.prefix_set_generation,
                        prefix_sets: self.prefix_config.config.clone(),
                    });
                }
                self.clients.insert(proto, tx);
            }
            Message::Unsubscribe { proto } => {
                self.clients.remove(&proto);
                for watches in [
                    &mut self.watch_prefix,
                    &mut self.watch_policy,
                    &mut self.watch_keychain,
                ] {
                    watches.retain(|_, entries| {
                        entries.retain(|watch| watch.proto != proto);
                        !entries.is_empty()
                    });
                }
            }
            Message::Register {
                proto,
                name,
                ident,
                policy_type,
            } => {
                // A task from a despawned protocol incarnation can still
                // have messages queued behind its Unsubscribe.  Never retain
                // a watch when there is no matching live client; in
                // particular it must not attach to a later respawn.
                if !self.clients.contains_key(&proto) {
                    return;
                }
                match policy_type {
                    PolicyType::PrefixSetIn | PolicyType::PrefixSetOut => {
                        // Always answer, even when the named set is
                        // absent (`prefix_set: None`): like a policy-list
                        // a bound-but-unresolved prefix-set is deny-all,
                        // so the subscriber must hear the `None` to clear
                        // a stale resolved set (e.g. after a rebind to an
                        // undefined name) and soft-reconfigure. Definition
                        // later replays via the `watch_prefix` entry below.
                        let prefix_set = self.prefix_config.config.get(&name).cloned();
                        if let Some(tx) = self.clients.get(&proto) {
                            let msg = PolicyRx::PrefixSet {
                                generation: self.prefix_set_generation,
                                name: name.clone(),
                                ident,
                                policy_type,
                                prefix_set,
                            };
                            let _ = tx.send(msg);
                        }
                        let watch = PolicyWatch {
                            proto,
                            ident,
                            policy_type,
                        };
                        self.watch_prefix.entry(name).or_default().push(watch);
                    }
                    PolicyType::PolicyListIn | PolicyType::PolicyListOut | PolicyType::TableMap => {
                        // Always answer, even when the named list is
                        // absent (`policy_list: None`). For a peer
                        // policy a bound-but-unresolved name is
                        // deny-all, so the subscriber must hear the
                        // `None` to clear any stale resolved policy
                        // (e.g. after a rebind from an existing name to
                        // an undefined one) and run a soft-reconfig that
                        // withdraws routes the now-missing policy no
                        // longer permits. A table-map likewise resyncs
                        // on `None`. Re-resolution once the name is
                        // later defined arrives via the `watch_policy`
                        // notification registered below.
                        let policy_list = self.policy_config.config.get(&name).cloned();
                        if let Some(tx) = self.clients.get(&proto) {
                            let msg = PolicyRx::PolicyList {
                                name: name.clone(),
                                ident,
                                policy_type,
                                policy_list,
                            };
                            let _ = tx.send(msg);
                        }
                        let watch = PolicyWatch {
                            proto,
                            ident,
                            policy_type,
                        };
                        self.watch_policy.entry(name).or_default().push(watch);
                    }
                    PolicyType::KeyChain(_) => {
                        if let Some(kc) = self.key_chain_config.config.get(&name)
                            && let Some(tx) = self.clients.get(&proto)
                        {
                            let msg = PolicyRx::KeyChain {
                                name: name.clone(),
                                ident,
                                policy_type,
                                key_chain: Some(kc.clone()),
                            };
                            let _ = tx.send(msg);
                        }
                        let watch = PolicyWatch {
                            proto,
                            ident,
                            policy_type,
                        };
                        self.watch_keychain.entry(name).or_default().push(watch);
                    }
                }
            }
            Message::Unregister {
                proto,
                name,
                ident,
                policy_type,
            } => {
                let map = match policy_type {
                    PolicyType::PrefixSetIn | PolicyType::PrefixSetOut => &mut self.watch_prefix,
                    PolicyType::PolicyListIn | PolicyType::PolicyListOut | PolicyType::TableMap => {
                        &mut self.watch_policy
                    }
                    PolicyType::KeyChain(_) => &mut self.watch_keychain,
                };
                if let Some(watches) = map.get_mut(&name) {
                    watches.retain(|w| {
                        !(w.proto == proto && w.ident == ident && w.policy_type == policy_type)
                    });
                    if watches.is_empty() {
                        map.remove(&name);
                    }
                }
                // Tell the subscriber it is no longer bound to `name`:
                // push a resolve reply carrying `None` so it clears any
                // stale resolved object and soft-reconfigures, exactly
                // like a `Register` to an undefined name (which already
                // "always answers, even with None" above). Previously
                // `Unregister` only dropped the watch, so an out-policy
                // *delete* left the peer's cached snapshot denying every
                // prefix and never re-advertised the routes the removed
                // policy had suppressed (review finding #12). Key-chain
                // unbinds ride `apply_ao_refresh_all`, not this path, and
                // the chain is shared config — a `None` here would wrongly
                // evict it — so they are skipped.
                let reply = match policy_type {
                    PolicyType::PrefixSetIn | PolicyType::PrefixSetOut => {
                        Some(PolicyRx::PrefixSet {
                            generation: self.prefix_set_generation,
                            name,
                            ident,
                            policy_type,
                            prefix_set: None,
                        })
                    }
                    PolicyType::PolicyListIn | PolicyType::PolicyListOut | PolicyType::TableMap => {
                        Some(PolicyRx::PolicyList {
                            name,
                            ident,
                            policy_type,
                            policy_list: None,
                        })
                    }
                    PolicyType::KeyChain(_) => None,
                };
                if let Some(reply) = reply
                    && let Some(tx) = self.clients.get(&proto)
                {
                    let _ = tx.send(reply);
                }
            }
        }
    }

    async fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let commit_ack = msg.commit_ack.clone();
        match msg.op {
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                if path.as_str().starts_with("/policy") {
                    let _ = self.policy_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/prefix-set") {
                    let _ = self.prefix_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/community-set") {
                    let _ = self.community_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/ext-community-set") {
                    let _ = self.ext_community_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/large-community-set") {
                    let _ = self.large_community_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/as-path-set") {
                    let _ = self.as_path_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/key-chains") {
                    let _ = self.key_chain_config.exec(path, args, msg.op);
                }
            }
            ConfigOp::CommitEnd => {
                // Capture which names are about to be touched directly,
                // before any of the per-set commits drain their caches.
                // Used after the direct syncs to find policies that
                // reference these sets indirectly (via `match prefix-set
                // X` etc.) and re-fire their watchers — without this
                // step, BGP peers attached to such policies wouldn't
                // see updates that flow through indirection.
                let changed_prefix_sets: std::collections::BTreeSet<String> =
                    self.prefix_config.cache.keys().cloned().collect();
                let changed_community_sets: std::collections::BTreeSet<String> =
                    self.community_config.cache.keys().cloned().collect();
                let changed_ext_community_sets: std::collections::BTreeSet<String> =
                    self.ext_community_config.cache.keys().cloned().collect();
                let changed_large_community_sets: std::collections::BTreeSet<String> =
                    self.large_community_config.cache.keys().cloned().collect();
                let changed_as_path_sets: std::collections::BTreeSet<String> =
                    self.as_path_config.cache.keys().cloned().collect();
                let changed_policies: std::collections::BTreeSet<String> =
                    self.policy_config.cache.keys().cloned().collect();

                // Delimit direct prefix-set watch notifications. Per-VRF BGP
                // buffers everything in this batch until BGP's own CommitEnd
                // marker, so a body edit of OLD cannot transiently replay OLD
                // when this same transaction rebinds OLD -> NEW.
                let next_prefix_set_generation = if msg.commit_generation == 0 {
                    self.prefix_set_generation.wrapping_add(1)
                } else {
                    msg.commit_generation
                };
                for (proto, tx) in &self.clients {
                    if proto.starts_with("bgp:vrf:") {
                        let _ = tx.send(PolicyRx::PrefixSetCommitStart {
                            generation: next_prefix_set_generation,
                        });
                    }
                }

                // Sync prefix-set.
                let syncer = PolicySyncer {
                    watch_map: &self.watch_prefix,
                    clients: &self.clients,
                    generation: next_prefix_set_generation,
                };
                PrefixSetConfig::commit(
                    &mut self.prefix_config.config,
                    &mut self.prefix_config.cache,
                    syncer,
                );
                self.prefix_set_generation = next_prefix_set_generation;
                for (proto, tx) in &self.clients {
                    if proto.starts_with("bgp:vrf:") {
                        let _ = tx.send(PolicyRx::PrefixSetInventory {
                            generation: self.prefix_set_generation,
                            prefix_sets: self.prefix_config.config.clone(),
                        });
                    }
                }
                // Sync key-chain. No cascade: key-chains aren't
                // referenced from any other policy entity, so a chain
                // edit only fans out to its direct subscribers.
                let kc_syncer = KeyChainSyncer {
                    watch_map: &self.watch_keychain,
                    clients: &self.clients,
                };
                KeyChainSetConfig::commit(
                    &mut self.key_chain_config.config,
                    &mut self.key_chain_config.cache,
                    kc_syncer,
                );
                // Sync community-set.
                self.community_config.commit();
                // Sync ext-community-set.
                self.ext_community_config.commit();
                // Sync large-community-set.
                self.large_community_config.commit();
                // Sync as-path-set.
                self.as_path_config.commit();

                // Sync policy-list.
                let syncer = PolicySyncer {
                    watch_map: &self.watch_policy,
                    clients: &self.clients,
                    generation: self.prefix_set_generation,
                };
                PolicyConfig::commit(
                    &mut self.policy_config.config,
                    &mut self.policy_config.cache,
                    &self.prefix_config,
                    &self.community_config,
                    &self.ext_community_config,
                    &self.large_community_config,
                    &self.as_path_config,
                    syncer,
                );

                // Cascade: a policy that wasn't itself edited may still
                // be stale if any of the prefix/community/as-path sets
                // it references were updated. Re-resolve those policies
                // against the freshly-committed sets and notify their
                // watchers so attached peers re-evaluate Adj-RIB-In.
                cascade_indirect_policy_updates(
                    &mut self.policy_config.config,
                    &self.prefix_config,
                    &self.community_config,
                    &self.ext_community_config,
                    &self.large_community_config,
                    &self.as_path_config,
                    &self.watch_policy,
                    &self.clients,
                    &changed_prefix_sets,
                    &changed_community_sets,
                    &changed_ext_community_sets,
                    &changed_large_community_sets,
                    &changed_as_path_sets,
                    &changed_policies,
                );
            }
            _ => {}
        }
        if let Some(commit_ack) = commit_ack {
            let _ = commit_ack.send(());
        }
    }

    async fn process_show_msg(&mut self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("{}", e),
            };
            let _ = msg.resp.send(output).await;
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg).await;
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg).await;
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
            }
        }
    }
}

/// Re-resolve and re-fire policies that *indirectly* reference any
/// of the changed sets, skipping policies that were already directly
/// committed in this same batch. This is what makes
///
///     set prefix-set hoge prefixes 2.2.2.2/32
///
/// reach a peer attached via `policy in <policy that matches
/// prefix-set hoge>` — the prefix-set edit alone wouldn't fire
/// `policy_list_update` for that policy without this cascade.
#[allow(clippy::too_many_arguments)]
fn cascade_indirect_policy_updates(
    policy_config: &mut BTreeMap<String, PolicyList>,
    prefix_config: &PrefixSetConfig,
    community_config: &CommunitySetConfig,
    ext_community_config: &ExtCommunitySetConfig,
    large_community_config: &LargeCommunitySetConfig,
    as_path_config: &AsPathSetConfig,
    watch_policy: &BTreeMap<String, Vec<PolicyWatch>>,
    clients: &BTreeMap<String, UnboundedSender<PolicyRx>>,
    changed_prefix_sets: &std::collections::BTreeSet<String>,
    changed_community_sets: &std::collections::BTreeSet<String>,
    changed_ext_community_sets: &std::collections::BTreeSet<String>,
    changed_large_community_sets: &std::collections::BTreeSet<String>,
    changed_as_path_sets: &std::collections::BTreeSet<String>,
    changed_policies: &std::collections::BTreeSet<String>,
) {
    if changed_prefix_sets.is_empty()
        && changed_community_sets.is_empty()
        && changed_ext_community_sets.is_empty()
        && changed_large_community_sets.is_empty()
        && changed_as_path_sets.is_empty()
    {
        return;
    }
    for (name, policy_list) in policy_config.iter_mut() {
        // Already fired by PolicyConfig::commit; the cache version
        // already saw the updated sets via `policy_entry_sync`.
        if changed_policies.contains(name) {
            continue;
        }
        let needs_resync = policy_list.entry.values().any(|e| {
            e.prefix_set_name
                .as_ref()
                .is_some_and(|n| changed_prefix_sets.contains(n))
                || e.community_set_name
                    .as_ref()
                    .is_some_and(|n| changed_community_sets.contains(n))
                || e.set_community
                    .as_ref()
                    .is_some_and(|c| changed_community_sets.contains(&c.name))
                || e.ext_community_set_name
                    .as_ref()
                    .is_some_and(|n| changed_ext_community_sets.contains(n))
                || e.large_community_set_name
                    .as_ref()
                    .is_some_and(|n| changed_large_community_sets.contains(n))
                || e.as_path_set_name
                    .as_ref()
                    .is_some_and(|n| changed_as_path_sets.contains(n))
        });
        if !needs_resync {
            continue;
        }
        policy_entry_sync(
            policy_list,
            prefix_config,
            community_config,
            ext_community_config,
            large_community_config,
            as_path_config,
        );
        if let Some(watches) = watch_policy.get(name) {
            for watch in watches {
                if let Some(tx) = clients.get(&watch.proto) {
                    let _ = tx.send(PolicyRx::PolicyList {
                        name: name.clone(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        policy_list: Some(policy_list.clone()),
                    });
                }
            }
        }
    }
}

pub fn serve(mut policy: Policy) {
    tokio::spawn(async move {
        policy.event_loop().await;
    });
}

#[cfg(test)]
mod unregister_reply_tests {
    use super::*;

    #[tokio::test]
    async fn register_after_unsubscribe_cannot_recreate_stale_watch() {
        let mut policy = Policy::new();
        let (old_tx, _old_rx) = mpsc::unbounded_channel::<PolicyRx>();
        policy
            .process_msg(Message::Subscribe {
                proto: "bgp:vrf:blue:policy:1".to_string(),
                tx: old_tx,
            })
            .await;
        policy
            .process_msg(Message::Unsubscribe {
                proto: "bgp:vrf:blue:policy:1".to_string(),
            })
            .await;

        // This is a queued message from the aborted old task.  The new task
        // has a different identity, and an absent old client makes Register
        // a no-op rather than leaving an orphan watcher behind.
        policy
            .process_msg(Message::Register {
                proto: "bgp:vrf:blue:policy:1".to_string(),
                name: "OLD".to_string(),
                ident: 7,
                policy_type: PolicyType::PrefixSetIn,
            })
            .await;
        assert!(!policy.watch_prefix.contains_key("OLD"));
    }

    /// Review finding #12: an out-policy *delete* must push a resolve
    /// reply carrying `None` so the subscriber clears its cached
    /// snapshot and re-advertises the routes the removed policy had
    /// suppressed. Previously `Unregister` only dropped the watch, so
    /// the peer kept denying every prefix forever.
    #[tokio::test]
    async fn unregister_policy_list_emits_clearing_reply() {
        let mut policy = Policy::new();
        let (tx, mut rx) = mpsc::unbounded_channel::<PolicyRx>();
        policy
            .process_msg(Message::Subscribe {
                proto: "bgp".to_string(),
                tx,
            })
            .await;

        policy
            .process_msg(Message::Unregister {
                proto: "bgp".to_string(),
                name: "DENY-ALL".to_string(),
                ident: 42,
                policy_type: PolicyType::PolicyListOut,
            })
            .await;

        match rx.try_recv() {
            Ok(PolicyRx::PolicyList {
                name,
                ident,
                policy_type,
                policy_list,
            }) => {
                assert_eq!(name, "DENY-ALL");
                assert_eq!(ident, 42);
                assert_eq!(policy_type, PolicyType::PolicyListOut);
                assert!(policy_list.is_none(), "unbind resolves to no policy");
            }
            other => panic!("expected a clearing PolicyList reply, got {other:?}"),
        }
    }

    /// The prefix-set unbind pushes the same clearing reply.
    #[tokio::test]
    async fn unregister_prefix_set_emits_clearing_reply() {
        let mut policy = Policy::new();
        let (tx, mut rx) = mpsc::unbounded_channel::<PolicyRx>();
        policy
            .process_msg(Message::Subscribe {
                proto: "bgp".to_string(),
                tx,
            })
            .await;
        policy
            .process_msg(Message::Unregister {
                proto: "bgp".to_string(),
                name: "PS-OUT".to_string(),
                ident: 7,
                policy_type: PolicyType::PrefixSetOut,
            })
            .await;
        assert!(
            matches!(
                rx.try_recv(),
                Ok(PolicyRx::PrefixSet {
                    prefix_set: None,
                    ..
                })
            ),
            "prefix-set unbind must push a None reply"
        );
    }

    /// A key-chain unbind must NOT push a reply — the chain is shared
    /// config; a `None` here would wrongly evict it, and key-chain
    /// unbinds ride `apply_ao_refresh_all` instead.
    #[tokio::test]
    async fn unregister_key_chain_emits_no_reply() {
        use crate::policy::KeyChainScope;
        let mut policy = Policy::new();
        let (tx, mut rx) = mpsc::unbounded_channel::<PolicyRx>();
        policy
            .process_msg(Message::Subscribe {
                proto: "bgp".to_string(),
                tx,
            })
            .await;
        policy
            .process_msg(Message::Unregister {
                proto: "bgp".to_string(),
                name: "KC".to_string(),
                ident: 1,
                policy_type: PolicyType::KeyChain(KeyChainScope::BgpNeighbor),
            })
            .await;
        assert!(rx.try_recv().is_err(), "key-chain unbind pushes nothing");
    }

    #[tokio::test]
    async fn vrf_subscriber_receives_initial_and_commit_final_prefix_inventory() {
        use ipnet::IpNet;

        use crate::policy::prefix::set::PrefixSetEntry;

        let mut policy = Policy::new();
        let (tx, mut rx) = mpsc::unbounded_channel::<PolicyRx>();
        policy
            .process_msg(Message::Subscribe {
                proto: "bgp:vrf:blue".to_string(),
                tx,
            })
            .await;
        assert!(matches!(
            rx.try_recv(),
            Ok(PolicyRx::PrefixSetInventory {
                generation: 0,
                prefix_sets,
            }) if prefix_sets.is_empty()
        ));

        let mut set = PrefixSet::default();
        set.insert(
            "198.51.100.0/24".parse::<IpNet>().unwrap(),
            PrefixSetEntry::default(),
        );
        policy
            .prefix_config
            .cache
            .insert("NEW".to_string(), set.clone());
        policy
            .process_cm_msg(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd))
            .await;

        assert!(matches!(
            rx.try_recv(),
            Ok(PolicyRx::PrefixSetCommitStart { generation: 1 })
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(PolicyRx::PrefixSetInventory {
                generation: 1,
                prefix_sets,
            }) if prefix_sets.get("NEW") == Some(&set)
        ));
    }

    #[tokio::test]
    async fn register_reply_uses_actor_current_prefix_set_generation() {
        use ipnet::IpNet;

        use crate::policy::prefix::set::PrefixSetEntry;

        let mut policy = Policy::new();
        let (tx, mut rx) = mpsc::unbounded_channel::<PolicyRx>();
        policy
            .process_msg(Message::Subscribe {
                proto: "bgp:vrf:blue".to_string(),
                tx,
            })
            .await;
        let _ = rx.try_recv(); // generation 0 inventory

        let mut first = PrefixSet::default();
        first.insert(
            "198.51.100.0/24".parse::<IpNet>().unwrap(),
            PrefixSetEntry::default(),
        );
        policy.prefix_config.cache.insert("NEW".to_string(), first);
        policy
            .process_cm_msg(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd))
            .await;
        let _ = rx.try_recv(); // generation 1 start
        let _ = rx.try_recv(); // generation 1 inventory

        let mut second = PrefixSet::default();
        second.insert(
            "203.0.113.0/24".parse::<IpNet>().unwrap(),
            PrefixSetEntry::default(),
        );
        policy
            .prefix_config
            .cache
            .insert("NEW".to_string(), second.clone());
        policy
            .process_cm_msg(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd))
            .await;
        let _ = rx.try_recv(); // generation 2 start
        let _ = rx.try_recv(); // generation 2 inventory

        // Models a Register from BGP commit 1 which reaches the actor only
        // after the actor has already published commit 2.
        policy
            .process_msg(Message::Register {
                proto: "bgp:vrf:blue".to_string(),
                name: "NEW".to_string(),
                ident: 17,
                policy_type: PolicyType::PrefixSetIn,
            })
            .await;
        assert!(matches!(
            rx.try_recv(),
            Ok(PolicyRx::PrefixSet {
                generation: 2,
                ident: 17,
                prefix_set: Some(prefix_set),
                ..
            }) if prefix_set == second
        ));
    }
}
