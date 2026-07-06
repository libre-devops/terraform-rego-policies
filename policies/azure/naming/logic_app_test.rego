package libredevops.naming.logic_app

import rego.v1

_logic(tf_type, name) := {"resource_changes": [{
	"address": sprintf("%s.%s", [tf_type, name]),
	"mode": "managed",
	"type": tf_type,
	"change": {"after": {"name": name}},
}]}

test_workflow_warns_on_bad_name if {
	count(warn) == 1 with input as _logic("azurerm_logic_app_workflow", "badname")
}

test_workflow_silent_on_good_name if {
	count(warn) == 0 with input as _logic("azurerm_logic_app_workflow", "logic-ldo-uks-prd-001")
}

test_standard_warns_on_bad_name if {
	count(warn) == 1 with input as _logic("azurerm_logic_app_standard", "badname")
}
