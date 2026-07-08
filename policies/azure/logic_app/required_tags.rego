# METADATA
# title: Logic App required tags
# description: >-
#   Logic Apps (Consumption or Standard) must carry the governance tags the Libre DevOps Logic App
#   standard mandates: hidden-title (the portal reads it as the resource subtitle), environment, and
#   managed-by. Informational (warn): visible in the report but it does not fail the build.
package libredevops.logicapp.required_tags

import data.lib.logicapp
import rego.v1

required := {"hidden-title", "environment", "managed-by"}

warn contains msg if {
	some rc in logicapp.logic_apps(input.resource_changes)
	tags := rc.change.after.tags
	is_object(tags)
	some key in required
	not _present(tags, key)
	msg := sprintf("logic app standard (info): %s is missing the required tag %q", [rc.address, key])
}

_present(tags, key) if {
	is_string(tags[key])
	trim_space(tags[key]) != ""
}
