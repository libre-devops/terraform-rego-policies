# METADATA
# title: Libre DevOps security helpers
# description: >-
#   Shared building blocks for the early-warning security policies. Everything here is defensive
#   about plan-time unknowns: a field that is not a known string or list is simply not matched, so a
#   computed value never breaks evaluation, it just is not checked yet.
package lib.security

import rego.v1

# Managed resource changes of a given Terraform type whose after object exists.
managed(changes, tf_type) := {rc |
	some rc in changes
	rc.mode == "managed"
	rc.type == tf_type
	is_object(rc.change.after)
}

# Source prefixes that mean "anywhere". Azure service tags Internet/Any and the wildcards.
internet_sources := {"*", "0.0.0.0/0", "internet", "any"}

# True when an NSG rule object (standalone resource after, or an inline security_rule entry) accepts
# traffic from anywhere.
internet_source(rule) if {
	is_string(rule.source_address_prefix)
	lower(rule.source_address_prefix) in internet_sources
}

internet_source(rule) if {
	some p in rule.source_address_prefixes
	is_string(p)
	lower(p) in internet_sources
}

# True when a single port-range string covers the given port: "*", the exact port, or an a-b range
# containing it.
port_covers("*", _)

port_covers(pr, want) if pr == format_int(want, 10)

port_covers(pr, want) if {
	parts := split(pr, "-")
	count(parts) == 2
	to_number(parts[0]) <= want
	want <= to_number(parts[1])
}

# True when the rule's destination ports (single range or list) cover the given port.
rule_ports_cover(rule, want) if {
	is_string(rule.destination_port_range)
	port_covers(rule.destination_port_range, want)
}

rule_ports_cover(rule, want) if {
	some pr in rule.destination_port_ranges
	is_string(pr)
	port_covers(pr, want)
}

# True when the rule allows inbound traffic.
allows_inbound(rule) if {
	is_string(rule.access)
	lower(rule.access) == "allow"
	is_string(rule.direction)
	lower(rule.direction) == "inbound"
}

# Every NSG rule in the plan as {address, rule} objects: standalone azurerm_network_security_rule
# resources plus each inline security_rule block of azurerm_network_security_group resources.
nsg_rules(changes) := standalone | inline if {
	standalone := {obj |
		some rc in managed(changes, "azurerm_network_security_rule")
		obj := {"address": rc.address, "rule": rc.change.after}
	}
	inline := {obj |
		some rc in managed(changes, "azurerm_network_security_group")
		some r in rc.change.after.security_rule
		obj := {"address": sprintf("%s (rule %q)", [rc.address, r.name]), "rule": r}
	}
}
