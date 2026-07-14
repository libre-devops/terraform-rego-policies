package libredevops.sentinel.detection_rule_prefer_nrt

import rego.v1

_rule(freq, query) := {"resource_changes": [{
	"address": "module.custom_detections.msgraph_resource.detection_rules[\"office-encoded-powershell\"]",
	"mode": "managed",
	"type": "msgraph_resource",
	"change": {"after": {
		"url": "security/rules/detectionRules",
		"body": {
			"schedule": {"frequency": freq},
			"queryCondition": {"queryText": query},
		},
	}},
}]}

_simple_query := "DeviceProcessEvents | where FileName == \"powershell.exe\" | project Timestamp, ReportId, DeviceId"

test_warns_when_eligible_rule_is_hourly if {
	count(warn) == 1 with input as _rule("PT1H", _simple_query)
}

test_silent_when_already_nrt if {
	count(warn) == 0 with input as _rule("PT0S", _simple_query)
}

test_silent_when_query_uses_join if {
	# A join disqualifies NRT, so the slower schedule is correct and not flagged.
	query := "DeviceProcessEvents | join DeviceNetworkEvents on DeviceId | project Timestamp, ReportId"
	count(warn) == 0 with input as _rule("PT1H", query)
}

test_silent_when_query_uses_union if {
	query := "union DeviceProcessEvents, DeviceFileEvents | project Timestamp, ReportId"
	count(warn) == 0 with input as _rule("PT3H", query)
}

test_silent_when_query_uses_externaldata if {
	query := "externaldata (x: string) [\"https://example.com/list\"] | project x"
	count(warn) == 0 with input as _rule("PT12H", query)
}

test_silent_when_query_has_comment if {
	query := "DeviceProcessEvents\n// a comment line\n| project Timestamp, ReportId"
	count(warn) == 0 with input as _rule("PT1H", query)
}

test_silent_when_frequency_unknown if {
	# A computed frequency is absent at plan time; nothing to check.
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "msgraph_resource.r",
		"mode": "managed",
		"type": "msgraph_resource",
		"change": {"after": {
			"url": "security/rules/detectionRules",
			"body": {"schedule": {}, "queryCondition": {"queryText": _simple_query}},
		}},
	}]}
}

test_ignores_non_detection_msgraph_resources if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "msgraph_resource.app",
		"mode": "managed",
		"type": "msgraph_resource",
		"change": {"after": {"url": "applications", "body": {"displayName": "x"}}},
	}]}
}
