# METADATA
# title: Sentinel automation rule expiration
# description: >-
#   A Sentinel automation rule with no expiration runs forever. That is fine for a permanent
#   routing rule, but a rule created for a temporary suppression, a campaign, or an incident-response
#   window should carry an expiration so it does not silently outlive its purpose. Informational
#   (warn): flags automation rules with no expiration_utc so the author confirms the rule is meant
#   to be permanent.
package libredevops.sentinel.automation_rule_expiration

import rego.v1

warn contains msg if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "azurerm_sentinel_automation_rule"
	is_object(rc.change.after)

	# expiration_utc absent or null at plan time (a computed value is treated as set, so nothing is
	# flagged on an unknown).
	not _has_expiration(rc.change.after)
	msg := sprintf("sentinel (info): %s has no expiration_utc; set one for temporary rules (suppression, campaign) so it does not outlive its purpose, or confirm it is permanent", [rc.address])
}

_has_expiration(after) if is_string(after.expiration_utc)
