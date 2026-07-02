package libredevops.naming.log_analytics_workspace

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_log_analytics_workspace.%s", [name]),
	"mode": "managed",
	"type": "azurerm_log_analytics_workspace",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("log-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_log_analytics_workspace.this", "mode": "managed", "type": "azurerm_log_analytics_workspace",
		"change": {"after": {}},
	}]}
}
