package libredevops.naming.logic_app_workflow

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_logic_app_workflow.%s", [name]),
	"mode": "managed",
	"type": "azurerm_logic_app_workflow",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("logic-ldo-uks-prd-001")
}
