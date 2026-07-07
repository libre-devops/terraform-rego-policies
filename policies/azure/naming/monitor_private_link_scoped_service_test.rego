package libredevops.naming.monitor_private_link_scoped_service

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_monitor_private_link_scoped_service.%s", [name]),
	"mode": "managed",
	"type": "azurerm_monitor_private_link_scoped_service",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("scoped-law-central")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_monitor_private_link_scoped_service.this", "mode": "managed", "type": "azurerm_monitor_private_link_scoped_service",
		"change": {"after": {}},
	}]}
}
