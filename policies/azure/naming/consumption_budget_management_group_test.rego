package libredevops.naming.consumption_budget_management_group

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_consumption_budget_management_group.%s", [name]),
	"mode": "managed",
	"type": "azurerm_consumption_budget_management_group",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("conbudg-ldo-uks-prd-001")
}
