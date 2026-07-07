package libredevops.naming.data_collection_rule_association

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_monitor_data_collection_rule_association.%s", [name]),
	"mode": "managed",
	"type": "azurerm_monitor_data_collection_rule_association",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("linuxbaseline")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("dcra-linux-baseline")
}

test_silent_on_the_mandated_endpoint_association_name if {
	count(warn) == 0 with input as _c("configurationAccessEndpoint")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_monitor_data_collection_rule_association.this", "mode": "managed", "type": "azurerm_monitor_data_collection_rule_association",
		"change": {"after": {}},
	}]}
}
