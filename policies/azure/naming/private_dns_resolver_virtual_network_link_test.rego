package libredevops.naming.private_dns_resolver_virtual_network_link

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_private_dns_resolver_virtual_network_link.%s", [name]),
	"mode": "managed",
	"type": "azurerm_private_dns_resolver_virtual_network_link",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("link-vnet-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_private_dns_resolver_virtual_network_link.this", "mode": "managed", "type": "azurerm_private_dns_resolver_virtual_network_link",
		"change": {"after": {}},
	}]}
}
