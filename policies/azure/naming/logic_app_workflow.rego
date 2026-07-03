# METADATA
# title: Logic App workflow naming
# description: >-
#   azurerm_logic_app_workflow names should follow the Libre DevOps convention (logic-ldo-uks-prd-001). Informational (warn):
#   visible in the report but it does not fail the build.
package libredevops.naming.logic_app_workflow

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_logic_app_workflow", "logic", "dashed")
	msg := naming.message(offender, "logic", "dashed")
}
