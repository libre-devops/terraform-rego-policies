package libredevops.naming.eventgrid_domain

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_eventgrid_domain.%s", [name]),
	"mode": "managed",
	"type": "azurerm_eventgrid_domain",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("evgd-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_eventgrid_domain.this", "mode": "managed", "type": "azurerm_eventgrid_domain",
		"change": {"after": {}},
	}]}
}
