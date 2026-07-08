package libredevops.logicapp.required_tags

import rego.v1

_wf(tags) := {"resource_changes": [{
	"address": "azurerm_logic_app_workflow.t",
	"mode": "managed",
	"type": "azurerm_logic_app_workflow",
	"change": {"after": {"name": "logic-ldo-uks-prd-001", "tags": tags}},
}]}

_full := {"hidden-title": "HTTP - does a thing", "environment": "prd", "managed-by": "terraform"}

test_silent_when_all_present if {
	count(warn) == 0 with input as _wf(_full)
}

test_warns_once_per_missing_tag if {
	count(warn) == 1 with input as _wf({"hidden-title": "x", "environment": "prd"})
}

test_warns_on_blank_tag_value if {
	count(warn) == 1 with input as _wf(object.union(_full, {"environment": "  "}))
}

test_silent_when_tags_unknown if {
	# tags computed at plan time: after.tags absent, nothing to check yet.
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_logic_app_workflow.t", "mode": "managed",
		"type": "azurerm_logic_app_workflow", "change": {"after": {"name": "logic-ldo-uks-prd-001"}},
	}]}
}

test_covers_standard_hosting if {
	count(warn) == 3 with input as {"resource_changes": [{
		"address": "azurerm_logic_app_standard.t", "mode": "managed",
		"type": "azurerm_logic_app_standard", "change": {"after": {"tags": {}}},
	}]}
}
