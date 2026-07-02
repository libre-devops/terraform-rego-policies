# METADATA
# title: NSG management ports open to the internet
# description: >-
#   Inbound Allow rules exposing SSH (22) or RDP (3389) to the internet are the classic brute-force
#   surface; use Bastion, a VPN, or just-in-time access instead. Covers standalone rules and inline
#   security_rule blocks. Informational (warn): visible in the report but it does not fail the build.
package libredevops.security.network_security_rule_management_ports

import data.lib.security
import rego.v1

management_ports := {22, 3389}

warn contains msg if {
	some entry in security.nsg_rules(input.resource_changes)
	security.allows_inbound(entry.rule)
	security.internet_source(entry.rule)
	some port in management_ports
	security.rule_ports_cover(entry.rule, port)
	msg := sprintf("security (info): %s exposes management port %d to the internet; prefer Bastion, VPN, or JIT access", [entry.address, port])
}
