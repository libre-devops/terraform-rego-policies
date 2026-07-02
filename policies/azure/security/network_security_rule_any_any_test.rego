package libredevops.security.network_security_rule_any_any

import rego.v1

_standalone(src, ports) := {"resource_changes": [{
	"address": "azurerm_network_security_rule.t",
	"mode": "managed",
	"type": "azurerm_network_security_rule",
	"change": {"after": {"name": "t", "access": "Allow", "direction": "Inbound", "source_address_prefix": src, "destination_port_range": ports}},
}]}

_inline(src, ports) := {"resource_changes": [{
	"address": "azurerm_network_security_group.t",
	"mode": "managed",
	"type": "azurerm_network_security_group",
	"change": {"after": {"name": "nsg-t", "security_rule": [{"name": "r1", "access": "Allow", "direction": "Inbound", "source_address_prefix": src, "destination_port_range": ports}]}},
}]}

test_warns_on_standalone_any_any if {
	count(warn) == 1 with input as _standalone("*", "*")
}

test_warns_on_inline_any_any if {
	count(warn) == 1 with input as _inline("0.0.0.0/0", "0-65535")
}

test_silent_on_single_port if {
	count(warn) == 0 with input as _standalone("*", "443")
}

test_silent_on_scoped_source if {
	count(warn) == 0 with input as _standalone("10.0.0.0/8", "*")
}

test_silent_on_deny if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_network_security_rule.t", "mode": "managed", "type": "azurerm_network_security_rule",
		"change": {"after": {"name": "t", "access": "Deny", "direction": "Inbound", "source_address_prefix": "*", "destination_port_range": "*"}},
	}]}
}
