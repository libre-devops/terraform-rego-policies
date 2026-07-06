package libredevops.naming.action_group

import rego.v1

_ag(name) := {"resource_changes": [{
	"address": sprintf("azurerm_monitor_action_group.%s", [name]),
	"mode": "managed",
	"type": "azurerm_monitor_action_group",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _ag("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _ag("ag-ldo-uks-prd-001")
}
