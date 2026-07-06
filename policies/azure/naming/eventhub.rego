# METADATA
# title: Event hub naming
# description: >-
#   azurerm_eventhub names should follow the Libre DevOps convention (evh-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventhub

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventhub", "evh", "dashed")
	msg := naming.message(offender, "evh", "dashed")
}
