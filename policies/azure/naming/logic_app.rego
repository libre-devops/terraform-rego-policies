# METADATA
# title: Logic app naming
# description: >-
#   Logic Apps use the logic- prefix whichever hosting model they are: Consumption
#   (azurerm_logic_app_workflow, Microsoft.Logic/workflows) or Standard (azurerm_logic_app_standard,
#   Microsoft.Web/sites). Informational (warn): visible in the report but it does not fail the
#   build.
package libredevops.naming.logic_app

import data.lib.naming
import rego.v1

_types := {"azurerm_logic_app_workflow", "azurerm_logic_app_standard"}

warn contains msg if {
	some tf_type in _types
	some offender in naming.offenders(input.resource_changes, tf_type, "logic", "dashed")
	msg := naming.message(offender, "logic", "dashed")
}
