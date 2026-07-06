package libredevops.naming.servicebus_subscription_rule

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_servicebus_subscription_rule.%s", [name]),
	"mode": "managed",
	"type": "azurerm_servicebus_subscription_rule",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("rule-high-severity-only")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_servicebus_subscription_rule.this", "mode": "managed", "type": "azurerm_servicebus_subscription_rule",
		"change": {"after": {}},
	}]}
}
