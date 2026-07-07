package libredevops.naming.eventgrid_system_topic_event_subscription

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_eventgrid_system_topic_event_subscription.%s", [name]),
	"mode": "managed",
	"type": "azurerm_eventgrid_system_topic_event_subscription",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("rotationaudittrail")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("evgs-rotation-audit-trail")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_eventgrid_system_topic_event_subscription.this", "mode": "managed", "type": "azurerm_eventgrid_system_topic_event_subscription",
		"change": {"after": {}},
	}]}
}
