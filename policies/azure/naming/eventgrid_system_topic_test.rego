package libredevops.naming.eventgrid_system_topic

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_eventgrid_system_topic.%s", [name]),
	"mode": "managed",
	"type": "azurerm_eventgrid_system_topic",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_warns_on_topic_prefix if {
	count(warn) == 1 with input as _c("evgt-ldo-uks-prd-001")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("egst-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_eventgrid_system_topic.this", "mode": "managed", "type": "azurerm_eventgrid_system_topic",
		"change": {"after": {}},
	}]}
}
