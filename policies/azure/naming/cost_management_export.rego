# METADATA
# title: Cost management export naming
# description: >-
#   Cost export names (subscription, resource group, and billing account scope) should follow the
#   Libre DevOps convention in its no-dash form (cmexportldouksprd001), since Azure only accepts
#   letters and numbers in export names. Informational (warn): visible in the report but it does not
#   fail the build.
package libredevops.naming.cost_management_export

import data.lib.naming
import rego.v1

export_types := {
	"azurerm_subscription_cost_management_export",
	"azurerm_resource_group_cost_management_export",
	"azurerm_billing_account_cost_management_export",
}

warn contains msg if {
	some tf_type in export_types
	some offender in naming.offenders(input.resource_changes, tf_type, "cmexport", "nodash")
	msg := naming.message(offender, "cmexport", "nodash")
}
