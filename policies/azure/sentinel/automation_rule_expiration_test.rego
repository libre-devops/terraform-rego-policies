package libredevops.sentinel.automation_rule_expiration

import rego.v1

_rule(after) := {"resource_changes": [{
	"address": "azurerm_sentinel_automation_rule.suppress_maintenance",
	"mode": "managed",
	"type": "azurerm_sentinel_automation_rule",
	"change": {"after": after},
}]}

test_warns_when_no_expiration if {
	count(warn) == 1 with input as _rule({"display_name": "Suppress during maintenance"})
}

test_silent_when_expiration_set if {
	count(warn) == 0 with input as _rule({"expiration_utc": "2026-12-31T23:59:00Z"})
}

test_silent_on_other_types if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_sentinel_alert_rule_scheduled.this",
		"mode": "managed",
		"type": "azurerm_sentinel_alert_rule_scheduled",
		"change": {"after": {"name": "x"}},
	}]}
}
