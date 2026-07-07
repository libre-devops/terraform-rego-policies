package libredevops.naming.private_dns_resolver_dns_forwarding_ruleset

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_private_dns_resolver_dns_forwarding_ruleset.%s", [name]),
	"mode": "managed",
	"type": "azurerm_private_dns_resolver_dns_forwarding_ruleset",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("dnsfrs-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_private_dns_resolver_dns_forwarding_ruleset.this", "mode": "managed", "type": "azurerm_private_dns_resolver_dns_forwarding_ruleset",
		"change": {"after": {}},
	}]}
}
