# METADATA
# title: Prefer near-real-time (NRT) for eligible custom detection rules
# description: >-
#   Defender XDR custom detection rules can run Continuous / near-real-time (NRT, an ISO 8601
#   frequency of PT0S): the rule evaluates events as they are ingested instead of on an hourly or
#   daily schedule, cutting time-to-detect from hours to seconds at minimal-to-no extra resource
#   cost. There is little reason not to use NRT for a rule that qualifies. A rule qualifies when its
#   query references a single table with no join, union, or externaldata operator and no comment
#   lines (the documented NRT constraints). This warns when an ELIGIBLE rule runs on a slower
#   schedule, and, so the reason is visible, stays silent when the query is ineligible (it explains
#   why the rule cannot be NRT). Informational (warn): does not fail the build.
package libredevops.sentinel.detection_rule_prefer_nrt

import rego.v1

# XDR custom detection rules deploy as msgraph_resource on the detectionRules collection.
_detection_rules := {rc |
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "msgraph_resource"
	is_object(rc.change.after)
	is_string(rc.change.after.url)
	contains(rc.change.after.url, "security/rules/detectionRules")
	is_object(rc.change.after.body)
}

# The operators and constructs that disqualify a query from NRT (a query using any of these must
# run on a schedule, so it is correctly not NRT and never flagged).
_nrt_blockers := ["\\bjoin\\b", "\\bunion\\b", "externaldata", "//"]

_query(after) := after.body.queryCondition.queryText

_frequency(after) := after.body.schedule.frequency

_nrt_eligible(after) if {
	is_string(_query(after))
	every blocker in _nrt_blockers {
		not regex.match(blocker, _query(after))
	}
}

warn contains msg if {
	some rc in _detection_rules
	after := rc.change.after
	is_string(_frequency(after))
	_frequency(after) != "PT0S"
	_nrt_eligible(after)
	msg := sprintf("sentinel (info): %s could run near-real-time (NRT): its query is a single table with no join, union, or externaldata, but it runs on frequency %s; consider PT0S (Continuous) for seconds-not-hours detection", [rc.address, _frequency(after)])
}
