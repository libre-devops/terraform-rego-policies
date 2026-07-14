package libredevops.sentinel.scheduled_rule_hygiene

import rego.v1

_rule(after) := {"resource_changes": [{
	"address": "module.alert_rule.azurerm_sentinel_alert_rule_scheduled.this[\"brute-force\"]",
	"mode": "managed",
	"type": "azurerm_sentinel_alert_rule_scheduled",
	"change": {"after": after},
}]}

_complete := {
	"tactics": ["CredentialAccess"],
	"techniques": ["T1110"],
	"entity_mapping": [{"entity_type": "Account"}],
}

test_silent_on_complete_rule if {
	count(warn) == 0 with input as _rule(_complete)
}

test_warns_once_per_missing_field if {
	# A rule with no context trips all three warnings.
	count(warn) == 3 with input as _rule({})
}

test_warns_on_missing_entity_mapping_only if {
	after := object.union(_complete, {"entity_mapping": []})
	count(warn) == 1 with input as _rule(after)
}

test_covers_nrt_rules if {
	count(warn) == 3 with input as {"resource_changes": [{
		"address": "azurerm_sentinel_alert_rule_nrt.this",
		"mode": "managed",
		"type": "azurerm_sentinel_alert_rule_nrt",
		"change": {"after": {}},
	}]}
}

test_silent_on_unknown_values if {
	# Computed lists are absent from change.after at plan time; nothing is flagged.
	count(warn) == 0 with input as _rule(_complete)
}

test_ignores_other_rule_kinds if {
	# Fusion, ML behaviour analytics, TI rules are template-driven and carry no tactics field.
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_sentinel_alert_rule_fusion.this",
		"mode": "managed",
		"type": "azurerm_sentinel_alert_rule_fusion",
		"change": {"after": {"name": "fusion"}},
	}]}
}
