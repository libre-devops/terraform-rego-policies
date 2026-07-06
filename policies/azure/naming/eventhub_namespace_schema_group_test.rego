package libredevops.naming.eventhub_namespace_schema_group

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_eventhub_namespace_schema_group.%s", [name]),
	"mode": "managed",
	"type": "azurerm_eventhub_namespace_schema_group",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("schemas-telemetry")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_eventhub_namespace_schema_group.this", "mode": "managed", "type": "azurerm_eventhub_namespace_schema_group",
		"change": {"after": {}},
	}]}
}
