# METADATA
# title: WAF policy naming (Application Gateway)
# description: >-
#   azurerm_web_application_firewall_policy names should follow the Libre DevOps convention
#   (waf-ldo-uks-prd-001). The agfw module's default derived name (waf-<gateway name>) also
#   satisfies the prefix. Informational (warn): visible in the report but it does not fail the
#   build.
package libredevops.naming.waf_policy

import data.lib.naming
import rego.v1

# The structured form is preferred; the derived waf-<gateway name> form (a waf- prefix on an
# already-conventioned gateway name) is also accepted.
_valid(name) if naming.valid(name, "waf", "dashed")

_valid(name) if regex.match(`^waf-agw-.+$`, name)

warn contains msg if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "azurerm_web_application_firewall_policy"
	name := rc.change.after.name
	is_string(name)
	not _valid(name)
	msg := sprintf(
		"naming (info): %s name %q does not match %s",
		[rc.address, name, naming.expected("waf", "dashed")],
	)
}
