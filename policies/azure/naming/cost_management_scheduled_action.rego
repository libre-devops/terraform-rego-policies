# METADATA
# title: Cost management scheduled action naming
# description: >-
#   azurerm_cost_management_scheduled_action names should follow the Libre DevOps convention in its
#   no-dash form (cmsaldouksprd001), keeping scheduled action names to letters and numbers. Cost
#   anomaly alerts share the ARM type but keep their own cmalert- convention (see
#   cost_anomaly_alert.rego). Informational (warn): visible in the report but it does not fail the
#   build.
package libredevops.naming.cost_management_scheduled_action

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_cost_management_scheduled_action", "cmsa", "nodash")
	msg := naming.message(offender, "cmsa", "nodash")
}
