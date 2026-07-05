package libredevops.naming.cognitive_account_project

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_cognitive_account_project.%s", [name]),
	"mode": "managed",
	"type": "azurerm_cognitive_account_project",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("aifp-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_cognitive_account_project.this", "mode": "managed", "type": "azurerm_cognitive_account_project",
		"change": {"after": {}},
	}]}
}
