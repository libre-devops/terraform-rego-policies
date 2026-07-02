package libredevops.security.role_assignment_broad_privilege

import rego.v1

_ra(role, scope) := {"resource_changes": [{
	"address": "azurerm_role_assignment.t",
	"mode": "managed",
	"type": "azurerm_role_assignment",
	"change": {"after": {"role_definition_name": role, "scope": scope}},
}]}

test_warns_on_subscription_owner if {
	count(warn) == 1 with input as _ra("Owner", "/subscriptions/00000000-0000-0000-0000-000000000000")
}

test_warns_on_mg_uaa if {
	count(warn) == 1 with input as _ra("User Access Administrator", "/providers/Microsoft.Management/managementGroups/mg-platform")
}

test_warns_on_guid_role_id if {
	count(warn) == 1 with input as {"resource_changes": [{
		"address": "azurerm_role_assignment.t", "mode": "managed", "type": "azurerm_role_assignment",
		"change": {"after": {"role_definition_id": "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "scope": "/subscriptions/00000000-0000-0000-0000-000000000000"}},
	}]}
}

test_silent_on_rg_owner if {
	count(warn) == 0 with input as _ra("Owner", "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app")
}

test_silent_on_reader_at_subscription if {
	count(warn) == 0 with input as _ra("Reader", "/subscriptions/00000000-0000-0000-0000-000000000000")
}

test_silent_when_scope_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_role_assignment.t", "mode": "managed", "type": "azurerm_role_assignment",
		"change": {"after": {"role_definition_name": "Owner"}},
	}]}
}
