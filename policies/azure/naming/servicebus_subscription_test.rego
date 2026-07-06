package libredevops.naming.servicebus_subscription

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_servicebus_subscription.%s", [name]),
	"mode": "managed",
	"type": "azurerm_servicebus_subscription",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("sbtsub-security-incidents")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_servicebus_subscription.this", "mode": "managed", "type": "azurerm_servicebus_subscription",
		"change": {"after": {}},
	}]}
}
