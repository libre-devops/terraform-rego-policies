# METADATA
# title: Cost management view naming
# description: >-
#   Saved cost view names (subscription and resource group scope) should follow the Libre DevOps
#   convention in its no-dash form (cmviewldouksprd001), keeping view names to letters and numbers.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.cost_management_view

import data.lib.naming
import rego.v1

view_types := {
	"azurerm_subscription_cost_management_view",
	"azurerm_resource_group_cost_management_view",
}

warn contains msg if {
	some tf_type in view_types
	some offender in naming.offenders(input.resource_changes, tf_type, "cmview", "nodash")
	msg := naming.message(offender, "cmview", "nodash")
}
