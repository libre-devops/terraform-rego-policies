# METADATA
# title: Action group naming
# description: >-
#   azurerm_monitor_action_group names should follow the Libre DevOps convention
#   (ag-ldo-uks-prd-001). Informational (warn): visible in the report but it does not fail the
#   build.
package libredevops.naming.action_group

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_monitor_action_group", "ag", "dashed")
	msg := naming.message(offender, "ag", "dashed")
}
