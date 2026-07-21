package libredevops.naming.cost_management_scheduled_action

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_cost_management_scheduled_action.%s", [name]),
	"mode": "managed",
	"type": "azurerm_cost_management_scheduled_action",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("monthly-report")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("cmsaldouksprd001")
}
