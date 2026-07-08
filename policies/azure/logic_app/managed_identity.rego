# METADATA
# title: Logic App managed identity
# description: >-
#   Logic Apps must run as a managed identity (SystemAssigned or UserAssigned) so connections
#   authenticate as the app, never a user account or a stored secret, per the Libre DevOps Logic App
#   standard. Informational (warn): visible in the report but it does not fail the build.
package libredevops.logicapp.managed_identity

import data.lib.logicapp
import rego.v1

valid_types := {"SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"}

warn contains msg if {
	some rc in logicapp.logic_apps(input.resource_changes)
	identities := rc.change.after.identity
	is_array(identities)
	not _has_managed_identity(identities)
	msg := sprintf("logic app standard (info): %s has no managed identity; connections must authenticate as the app, never a user account or stored secret", [rc.address])
}

_has_managed_identity(identities) if {
	some id in identities
	is_string(id.type)
	id.type in valid_types
}
