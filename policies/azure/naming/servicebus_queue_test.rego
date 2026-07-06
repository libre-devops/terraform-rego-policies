package libredevops.naming.servicebus_queue

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_servicebus_queue.%s", [name]),
	"mode": "managed",
	"type": "azurerm_servicebus_queue",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("sbq-incident-intake")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_servicebus_queue.this", "mode": "managed", "type": "azurerm_servicebus_queue",
		"change": {"after": {}},
	}]}
}
