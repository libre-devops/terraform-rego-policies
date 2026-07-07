package libredevops.naming.eventgrid_domain_topic

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_eventgrid_domain_topic.%s", [name]),
	"mode": "managed",
	"type": "azurerm_eventgrid_domain_topic",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("orders")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("evgdt-orders")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_eventgrid_domain_topic.this", "mode": "managed", "type": "azurerm_eventgrid_domain_topic",
		"change": {"after": {}},
	}]}
}
