package libredevops.naming.resource_group

import rego.v1

_change(name) := {"resource_changes": [{
	"address": sprintf("azurerm_resource_group.%s", [name]),
	"mode": "managed",
	"type": "azurerm_resource_group",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _change("myresourcegroup")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _change("rg-ldo-uks-prd")
}

test_silent_on_good_name_with_optional_and_number if {
	count(warn) == 0 with input as _change("rg-ldo-uks-prd-mgt-001")
}

test_silent_on_three_digit_number if {
	count(warn) == 0 with input as _change("rg-ldo-uks-prd-001")
}

test_warns_on_legacy_two_digit_number if {
	# The ordinal must be three digits now (001), so a legacy two-digit ordinal no longer matches.
	count(warn) == 1 with input as _change("rg-ldo-uks-prd-01")
}

test_silent_when_name_unknown if {
	# A computed name is absent from change.after at plan time; nothing to check.
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_resource_group.this",
		"mode": "managed",
		"type": "azurerm_resource_group",
		"change": {"after": {}},
	}]}
}

test_ignores_other_resource_types if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_storage_account.this",
		"mode": "managed",
		"type": "azurerm_storage_account",
		"change": {"after": {"name": "whatever"}},
	}]}
}
