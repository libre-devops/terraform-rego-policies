# METADATA
# title: Event Grid topic naming
# description: >-
#   azurerm_eventgrid_topic names should follow the Libre DevOps convention (evgt-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventgrid_topic

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventgrid_topic", "evgt", "dashed")
	msg := naming.message(offender, "evgt", "dashed")
}
