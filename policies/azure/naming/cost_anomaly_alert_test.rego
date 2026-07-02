package libredevops.naming.cost_anomaly_alert

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_cost_anomaly_alert.%s", [name]),
	"mode": "managed",
	"type": "azurerm_cost_anomaly_alert",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("cmalert-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_cost_anomaly_alert.this", "mode": "managed", "type": "azurerm_cost_anomaly_alert",
		"change": {"after": {}},
	}]}
}
