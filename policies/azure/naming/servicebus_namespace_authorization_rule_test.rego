package libredevops.naming.servicebus_namespace_authorization_rule

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_servicebus_namespace_authorization_rule.%s", [name]),
	"mode": "managed",
	"type": "azurerm_servicebus_namespace_authorization_rule",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("rule-legacy-sender")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_servicebus_namespace_authorization_rule.this", "mode": "managed", "type": "azurerm_servicebus_namespace_authorization_rule",
		"change": {"after": {}},
	}]}
}
