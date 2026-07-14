# METADATA
# title: Sentinel scheduled and NRT alert rule hygiene
# description: >-
#   Scheduled and near-real-time Sentinel analytics rules that raise incidents should carry the
#   triage context an analyst needs: MITRE ATT&CK tactics, techniques, and entity mappings. A rule
#   with none of these fires a bare alert with nothing to pivot on. Informational (warn): surfaced
#   in the report, does not fail the build.
package libredevops.sentinel.scheduled_rule_hygiene

import rego.v1

# The alert-rule resource types this pack covers (both raise incidents on a schedule).
rule_types := {"azurerm_sentinel_alert_rule_scheduled", "azurerm_sentinel_alert_rule_nrt"}

# Managed rule changes with an after object.
_rules := {rc |
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type in rule_types
	is_object(rc.change.after)
}

# A field is "present" when it is a known non-empty list at plan time. A computed/unknown value is
# not matched, so nothing is flagged on a value Terraform has not resolved yet.
_has_list(after, key) if {
	is_array(after[key])
	count(after[key]) > 0
}

warn contains msg if {
	some rc in _rules
	not _has_list(rc.change.after, "tactics")
	msg := sprintf("sentinel (info): %s declares no MITRE tactics; add tactics so the alert is triageable", [rc.address])
}

warn contains msg if {
	some rc in _rules
	not _has_list(rc.change.after, "techniques")
	msg := sprintf("sentinel (info): %s declares no MITRE techniques; add techniques for ATT&CK coverage reporting", [rc.address])
}

warn contains msg if {
	some rc in _rules
	not _has_list(rc.change.after, "entity_mapping")
	msg := sprintf("sentinel (info): %s declares no entity_mapping; mapped entities drive incident correlation and SOAR enrichment", [rc.address])
}
