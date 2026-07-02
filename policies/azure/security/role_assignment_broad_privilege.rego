# METADATA
# title: Privileged roles at wide scopes
# description: >-
#   Owner, User Access Administrator, or Role Based Access Control Administrator granted at a whole
#   subscription or management group is a very large blast radius; scope privileged grants down, and
#   pair Owner with a delegation condition (the role-assignment module applies one by default).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.security.role_assignment_broad_privilege

import data.lib.security
import rego.v1

privileged_names := {"owner", "user access administrator", "role based access control administrator"}

privileged_guids := {
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635", # Owner
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", # User Access Administrator
	"f58310d9-a9f6-439a-9e8d-f62e7b41a168", # Role Based Access Control Administrator
}

is_privileged(after) if {
	is_string(after.role_definition_name)
	lower(after.role_definition_name) in privileged_names
}

is_privileged(after) if {
	is_string(after.role_definition_id)
	some guid in privileged_guids
	endswith(lower(after.role_definition_id), guid)
}

wide_scope(scope) if regex.match(`^/subscriptions/[^/]+$`, scope)

wide_scope(scope) if startswith(lower(scope), "/providers/microsoft.management/managementgroups/")

warn contains msg if {
	some rc in security.managed(input.resource_changes, "azurerm_role_assignment")
	is_privileged(rc.change.after)
	is_string(rc.change.after.scope)
	wide_scope(rc.change.after.scope)
	msg := sprintf("security (info): %s grants a privileged role at the wide scope %q; scope privileged access down", [rc.address, rc.change.after.scope])
}
