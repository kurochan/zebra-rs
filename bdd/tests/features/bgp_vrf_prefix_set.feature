@serial
@bgp_vrf_prefix_set
Feature: Per-VRF BGP neighbor prefix-set filtering
  As a network operator
  I want an AFI-scoped prefix-set on a per-VRF CE neighbor
  So routes learned from one CE are not leaked to another CE.

  Topology:
  ```text
  peer-a (AS65002) ---- router/vrf-blue (AS65001) ---- peer-b (AS65003)
  ```

  peer-a originates exact, more-specific, and non-matching IPv4/IPv6
  prefixes. Inbound filters admit the exact and more-specific routes;
  the initial outbound filters toward peer-b admit only the exact routes.

  Scenario: Establish the per-VRF sessions with an outbound filter
    Given a clean test environment
    When I create namespace "peer-a"
    And I create namespace "router"
    And I create namespace "peer-b"
    And I connect namespace "peer-a" interface "router" to namespace "router" interface "peer-a"
    And I connect namespace "router" interface "peer-b" to namespace "peer-b" interface "router"
    And I start zebra-rs in namespace "peer-a"
    And I start zebra-rs in namespace "router"
    And I start zebra-rs in namespace "peer-b"
    And I apply config "peer-a.yaml" to namespace "peer-a"
    And I apply config "router-initial.yaml" to namespace "router"
    And I apply config "peer-b.yaml" to namespace "peer-b"
    # The IPv6 route can arrive just after peer-b's initial sync and then
    # follows the default eBGP MRAI; wait through that legitimate debounce.
    And I wait 35 seconds for BGP to operate
    Then BGP session in "peer-a" to "192.0.2.1" should be "Established"
    And BGP session in "peer-b" to "192.0.2.5" should be "Established"
    And show command "show bgp vrf vrf-blue" in namespace "router" should contain "198.51.100.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "router" should contain "203.0.113.128/25"
    And show command "show bgp vrf vrf-blue" in namespace "router" should not contain "100.64.0.0/24"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should contain "2001:db8:100::/48"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should contain "2001:db8:200:1::/64"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should not contain "2001:db8:300::/48"
    And BGP route in "peer-b" has "198.51.100.0/24"
    And BGP route in "peer-b" does not have "203.0.113.128/25"
    And show command "show bgp ipv6" in namespace "peer-b" should contain "2001:db8:100::/48"
    And show command "show bgp ipv6" in namespace "peer-b" should not contain "2001:db8:200:1::/64"

  Scenario: Show reports resolved per-AFI prefix-set bindings
    Given the per-VRF prefix-set topology exists
    Then show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Address family: IPv4 Unicast"
    And show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Prefix-set in:  PEER-IN-V4"
    And show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Prefix-set out: PEER-OUT-V4"
    And show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Address family: IPv6 Unicast"
    And show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Prefix-set in:  PEER-IN-V6"
    And show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Prefix-set out: PEER-OUT-V6"
    And show JSON policy binding for scope "ipv4" from command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should have in "PEER-IN-V4" resolved true and out "PEER-OUT-V4" resolved true
    And show JSON policy binding for scope "ipv6" from command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should have in "PEER-IN-V6" resolved true and out "PEER-OUT-V6" resolved true

  Scenario: A live inbound edit replays Adj-RIB-In without reset
    Given the per-VRF prefix-set topology exists
    When I remember BGP counters in "peer-a" to "192.0.2.1"
    When I apply config "router-inbound-other.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then BGP session in "peer-a" to "192.0.2.1" should be "Established"
    And BGP session in "peer-a" to "192.0.2.1" should not have reset since remembered
    And show command "show bgp vrf vrf-blue" in namespace "router" should not contain "198.51.100.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "router" should contain "203.0.113.128/25"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should not contain "2001:db8:100::/48"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should contain "2001:db8:200:1::/64"
    When I apply config "router-initial.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then BGP session in "peer-a" to "192.0.2.1" should be "Established"
    And show command "show bgp vrf vrf-blue" in namespace "router" should contain "198.51.100.0/24"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should contain "2001:db8:100::/48"

  Scenario: A live outbound edit withdraws and advertises without reset
    Given the per-VRF prefix-set topology exists
    When I remember BGP counters in "peer-b" to "192.0.2.5"
    When I apply config "router-other.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then BGP session in "peer-b" to "192.0.2.5" should be "Established"
    And BGP session in "peer-b" to "192.0.2.5" should not have reset since remembered
    And BGP route in "peer-b" does not have "198.51.100.0/24"
    And BGP route in "peer-b" has "203.0.113.128/25"
    And show command "show bgp ipv6" in namespace "peer-b" should not contain "2001:db8:100::/48"
    And show command "show bgp ipv6" in namespace "peer-b" should contain "2001:db8:200:1::/64"

  Scenario: Deleting a referenced prefix-set body fail-closes both families
    Given the per-VRF prefix-set topology exists
    When I remember BGP counters in "peer-b" to "192.0.2.5"
    And I apply config "router-body-deleted.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then BGP session in "peer-b" to "192.0.2.5" should be "Established"
    And BGP session in "peer-b" to "192.0.2.5" should not have reset since remembered
    And show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Prefix-set out: PEER-OUT-V4 (unresolved)"
    And show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Prefix-set out: PEER-OUT-V6 (unresolved)"
    And BGP route in "peer-b" does not have "198.51.100.0/24"
    And BGP route in "peer-b" does not have "203.0.113.128/25"
    And show command "show bgp ipv6" in namespace "peer-b" should not contain "2001:db8:100::/48"
    And show command "show bgp ipv6" in namespace "peer-b" should not contain "2001:db8:200:1::/64"
    When I apply config "router-initial.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then BGP route in "peer-b" has "198.51.100.0/24"
    And show command "show bgp ipv6" in namespace "peer-b" should contain "2001:db8:100::/48"
    And BGP session in "peer-b" to "192.0.2.5" should not have reset since remembered

  Scenario: An unresolved reference fail-closes and later resolves
    Given the per-VRF prefix-set topology exists
    When I remember BGP counters in "peer-b" to "192.0.2.5"
    And I apply config "router-unresolved.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Prefix-set out: MISSING (unresolved)"
    And show command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should contain "Prefix-set out: MISSING6 (unresolved)"
    And show JSON policy binding for scope "ipv4" from command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should have in "PEER-IN-V4" resolved true and out "MISSING" resolved false
    And show JSON policy binding for scope "ipv6" from command "show bgp vrf vrf-blue neighbor 192.0.2.6" in namespace "router" should have in "PEER-IN-V6" resolved true and out "MISSING6" resolved false
    And BGP session in "peer-b" to "192.0.2.5" should not have reset since remembered
    And BGP route in "peer-b" does not have "198.51.100.0/24"
    And BGP route in "peer-b" does not have "203.0.113.128/25"
    And show command "show bgp ipv6" in namespace "peer-b" should not contain "2001:db8:100::/48"
    And show command "show bgp ipv6" in namespace "peer-b" should not contain "2001:db8:200:1::/64"
    And BGP session in "peer-b" to "192.0.2.5" should not have reset since remembered
    When I apply config "router-resolved.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then BGP session in "peer-b" to "192.0.2.5" should be "Established"
    And BGP route in "peer-b" has "198.51.100.0/24"
    And BGP route in "peer-b" does not have "203.0.113.128/25"
    And show command "show bgp ipv6" in namespace "peer-b" should contain "2001:db8:100::/48"
    And show command "show bgp ipv6" in namespace "peer-b" should not contain "2001:db8:200:1::/64"

  Scenario: An unresolved inbound reference fail-closes and later replays Adj-RIB-In
    Given the per-VRF prefix-set topology exists
    When I remember BGP counters in "peer-a" to "192.0.2.1"
    And I apply config "router-inbound-unresolved.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then show command "show bgp vrf vrf-blue neighbor 192.0.2.2" in namespace "router" should contain "Prefix-set in:  MISSING-IN (unresolved)"
    And show command "show bgp vrf vrf-blue neighbor 192.0.2.2" in namespace "router" should contain "Prefix-set in:  MISSING6-IN (unresolved)"
    And show command "show bgp vrf vrf-blue" in namespace "router" should not contain "198.51.100.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "router" should not contain "203.0.113.128/25"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should not contain "2001:db8:100::/48"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should not contain "2001:db8:200:1::/64"
    When I apply config "router-inbound-resolved.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then BGP session in "peer-a" to "192.0.2.1" should not have reset since remembered
    And show command "show bgp vrf vrf-blue" in namespace "router" should contain "198.51.100.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "router" should not contain "203.0.113.128/25"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should contain "2001:db8:100::/48"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should not contain "2001:db8:200:1::/64"
    When I apply config "router-resolved.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate

  Scenario: Reapplying identical bindings sends no UPDATE and resets no session
    Given the per-VRF prefix-set topology exists
    When I remember BGP counters in "peer-b" to "192.0.2.5"
    And I apply config "router-resolved.yaml" to namespace "router"
    And I wait 3 seconds for BGP to operate
    Then BGP session in "peer-b" to "192.0.2.5" should not have reset since remembered
    And BGP UPDATE count in "peer-b" to "192.0.2.5" should be unchanged since remembered

  Scenario: Deleting the binding restores unfiltered behavior
    Given the per-VRF prefix-set topology exists
    When I remember BGP counters in "peer-a" to "192.0.2.1"
    And I remember BGP counters in "peer-b" to "192.0.2.5"
    And I apply command "delete router bgp vrf vrf-blue neighbor 192.0.2.6 afi-safi ipv4 prefix-set out MISSING" in namespace "router"
    And I apply command "delete router bgp vrf vrf-blue neighbor 192.0.2.6 afi-safi ipv6 prefix-set out MISSING6" in namespace "router"
    And I apply command "delete router bgp vrf vrf-blue neighbor 192.0.2.2 afi-safi ipv4 prefix-set in PEER-IN-V4" in namespace "router"
    And I apply command "delete router bgp vrf vrf-blue neighbor 192.0.2.2 afi-safi ipv6 prefix-set in PEER-IN-V6" in namespace "router"
    # Removing the inbound binding admits previously filtered routes. Their
    # first advertisement to peer-b legitimately follows the eBGP MRAI.
    And I wait 35 seconds for BGP to operate
    Then BGP session in "peer-b" to "192.0.2.5" should be "Established"
    And BGP session in "peer-a" to "192.0.2.1" should not have reset since remembered
    And BGP session in "peer-b" to "192.0.2.5" should not have reset since remembered
    And show command "show bgp vrf vrf-blue" in namespace "router" should contain "100.64.0.0/24"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "router" should contain "2001:db8:300::/48"
    And BGP route in "peer-b" has "198.51.100.0/24"
    And BGP route in "peer-b" has "203.0.113.128/25"
    And BGP route in "peer-b" has "100.64.0.0/24"
    And show command "show bgp ipv6" in namespace "peer-b" should contain "2001:db8:100::/48"
    And show command "show bgp ipv6" in namespace "peer-b" should contain "2001:db8:200:1::/64"
    And show command "show bgp ipv6" in namespace "peer-b" should contain "2001:db8:300::/48"

  Scenario: Default and multiple VRFs keep route and binding state isolated
    Given the per-VRF prefix-set topology exists
    When I create namespace "iso-default"
    And I create namespace "iso-blue"
    And I create namespace "iso-red"
    And I create namespace "iso-router"
    And I connect namespace "iso-default" interface "iso-router" to namespace "iso-router" interface "iso-default"
    And I connect namespace "iso-blue" interface "iso-router" to namespace "iso-router" interface "iso-blue"
    And I connect namespace "iso-red" interface "iso-router" to namespace "iso-router" interface "iso-red"
    And I start zebra-rs in namespace "iso-default"
    And I start zebra-rs in namespace "iso-blue"
    And I start zebra-rs in namespace "iso-red"
    And I start zebra-rs in namespace "iso-router"
    And I apply config "isolation-default.yaml" to namespace "iso-default"
    And I apply config "isolation-blue.yaml" to namespace "iso-blue"
    And I apply config "isolation-red.yaml" to namespace "iso-red"
    And I apply config "isolation-router.yaml" to namespace "iso-router"
    And I wait 35 seconds for BGP to operate
    Then BGP session in "iso-default" to "192.0.2.9" should be "Established"
    And BGP session in "iso-blue" to "192.0.2.13" should be "Established"
    And BGP session in "iso-red" to "192.0.2.17" should be "Established"
    And show command "show bgp" in namespace "iso-router" should contain "10.10.0.0/24"
    And show command "show bgp" in namespace "iso-router" should contain "10.10.99.0/24"
    And show command "show bgp" in namespace "iso-router" should not contain "10.20.0.0/24"
    And show command "show bgp vrf iso-blue" in namespace "iso-router" should contain "10.20.0.0/24"
    And show command "show bgp vrf iso-blue" in namespace "iso-router" should not contain "10.20.99.0/24"
    And show command "show bgp vrf iso-blue" in namespace "iso-router" should not contain "10.30.0.0/24"
    And show command "show bgp vrf iso-red" in namespace "iso-router" should contain "10.30.0.0/24"
    And show command "show bgp vrf iso-red" in namespace "iso-router" should not contain "10.30.99.0/24"
    And show command "show bgp vrf iso-red" in namespace "iso-router" should not contain "10.20.0.0/24"
    And show command "show bgp vrf iso-blue neighbor 192.0.2.14" in namespace "iso-router" should contain "Prefix-set in:  SHARED-IN"
    And show command "show bgp vrf iso-red neighbor 192.0.2.18" in namespace "iso-router" should contain "Prefix-set in:  SHARED-IN"
    And show command "show bgp vrf iso-blue neighbor 192.0.2.14" in namespace "iso-router" should contain "Prefix-set out: BLUE-OUT"
    And show command "show bgp vrf iso-red neighbor 192.0.2.18" in namespace "iso-router" should contain "Prefix-set out: RED-OUT"
    And BGP route in "iso-blue" has "10.21.0.0/24"
    And BGP route in "iso-blue" does not have "10.21.99.0/24"
    And BGP route in "iso-blue" does not have "10.31.0.0/24"
    And BGP route in "iso-red" has "10.31.0.0/24"
    And BGP route in "iso-red" does not have "10.31.99.0/24"
    And BGP route in "iso-red" does not have "10.21.0.0/24"
    When I stop zebra-rs in namespace "iso-default"
    And I stop zebra-rs in namespace "iso-blue"
    And I stop zebra-rs in namespace "iso-red"
    And I stop zebra-rs in namespace "iso-router"
    And I delete namespace "iso-default"
    And I delete namespace "iso-blue"
    And I delete namespace "iso-red"
    And I delete namespace "iso-router"

  Scenario: Teardown topology
    Given the per-VRF prefix-set topology exists
    When I stop zebra-rs in namespace "peer-a"
    And I stop zebra-rs in namespace "router"
    And I stop zebra-rs in namespace "peer-b"
    And I delete namespace "peer-a"
    And I delete namespace "router"
    And I delete namespace "peer-b"
    Then the test environment should be clean
