package libredevops.logicapp.managed_identity

import rego.v1

_wf(identity) := {"resource_changes": [{
	"address": "azurerm_logic_app_workflow.t",
	"mode": "managed",
	"type": "azurerm_logic_app_workflow",
	"change": {"after": {"name": "logic-ldo-uks-prd-001", "identity": identity}},
}]}

test_silent_on_user_assigned if {
	count(warn) == 0 with input as _wf([{"type": "UserAssigned", "identity_ids": ["/subscriptions/x/id"]}])
}

test_silent_on_system_assigned if {
	count(warn) == 0 with input as _wf([{"type": "SystemAssigned"}])
}

test_warns_on_empty_identity if {
	count(warn) == 1 with input as _wf([])
}

test_warns_on_unrecognised_type if {
	count(warn) == 1 with input as _wf([{"type": "None"}])
}

test_silent_when_identity_unknown if {
	# identity computed at plan time: after.identity absent, nothing to check yet.
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_logic_app_workflow.t", "mode": "managed",
		"type": "azurerm_logic_app_workflow", "change": {"after": {"name": "logic-ldo-uks-prd-001"}},
	}]}
}
