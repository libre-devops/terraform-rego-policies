package libredevops.security.network_security_rule_management_ports

import rego.v1

_rule(src, ports) := {"resource_changes": [{
	"address": "azurerm_network_security_rule.t",
	"mode": "managed",
	"type": "azurerm_network_security_rule",
	"change": {"after": {"name": "t", "access": "Allow", "direction": "Inbound", "source_address_prefix": src, "destination_port_range": ports}},
}]}

test_warns_on_internet_ssh if {
	count(warn) == 1 with input as _rule("Internet", "22")
}

test_warns_on_rdp_in_range if {
	count(warn) == 1 with input as _rule("*", "3000-4000")
}

test_warns_on_port_list if {
	count(warn) == 1 with input as {"resource_changes": [{
		"address": "azurerm_network_security_rule.t", "mode": "managed", "type": "azurerm_network_security_rule",
		"change": {"after": {"name": "t", "access": "Allow", "direction": "Inbound", "source_address_prefix": "*", "destination_port_ranges": ["443", "22"]}},
	}]}
}

test_silent_on_scoped_source if {
	count(warn) == 0 with input as _rule("192.168.0.0/24", "22")
}

test_silent_on_https if {
	count(warn) == 0 with input as _rule("Internet", "443")
}
