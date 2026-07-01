package libredevops.naming.route_table

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_route_table.%s", [name]),
	"mode": "managed",
	"type": "azurerm_route_table",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("rt-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_route_table.this", "mode": "managed", "type": "azurerm_route_table",
		"change": {"after": {}},
	}]}
}
