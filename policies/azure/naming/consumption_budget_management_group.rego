# METADATA
# title: Management group consumption budget naming
# description: >-
#   azurerm_consumption_budget_management_group names should follow the Libre DevOps convention
#   (conbudg-ldo-uks-prd-001). Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.consumption_budget_management_group

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_consumption_budget_management_group", "conbudg", "dashed")
	msg := naming.message(offender, "conbudg", "dashed")
}
