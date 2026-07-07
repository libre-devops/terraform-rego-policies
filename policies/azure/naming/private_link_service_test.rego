package libredevops.naming.private_link_service

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_private_link_service.%s", [name]),
	"mode": "managed",
	"type": "azurerm_private_link_service",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("pl-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_private_link_service.this", "mode": "managed", "type": "azurerm_private_link_service",
		"change": {"after": {}},
	}]}
}
