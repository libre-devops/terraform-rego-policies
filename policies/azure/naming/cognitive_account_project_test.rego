package libredevops.naming.cognitive_account_project

import rego.v1

_azurerm(name) := {"resource_changes": [{
	"address": sprintf("azurerm_cognitive_account_project.%s", [name]),
	"mode": "managed",
	"type": "azurerm_cognitive_account_project",
	"change": {"after": {"name": name}},
}]}

_azapi(name) := {"resource_changes": [{
	"address": sprintf("azapi_resource.%s", [name]),
	"mode": "managed",
	"type": "azapi_resource",
	"change": {"after": {"name": name, "type": "Microsoft.CognitiveServices/accounts/projects@2025-09-01"}},
}]}

test_azurerm_warns_on_bad_name if {
	count(warn) == 1 with input as _azurerm("badname")
}

test_azurerm_silent_on_good_name if {
	count(warn) == 0 with input as _azurerm("aifp-ldo-uks-prd-001")
}

test_azapi_warns_on_bad_name if {
	count(warn) == 1 with input as _azapi("badname")
}

test_azapi_silent_on_good_name if {
	count(warn) == 0 with input as _azapi("aifp-ldo-uks-prd-001")
}

# An azapi resource of a different type must not be checked by this policy.
test_azapi_other_type_ignored if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azapi_resource.other", "mode": "managed", "type": "azapi_resource",
		"change": {"after": {"name": "badname", "type": "Microsoft.Web/connections@2016-06-01"}},
	}]}
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azapi_resource.this", "mode": "managed", "type": "azapi_resource",
		"change": {"after": {"type": "Microsoft.CognitiveServices/accounts/projects@2025-09-01"}},
	}]}
}
