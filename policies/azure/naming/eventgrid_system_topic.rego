# METADATA
# title: Event Grid system topic naming
# description: >-
#   azurerm_eventgrid_system_topic names should follow the Libre DevOps convention (egst-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventgrid_system_topic

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventgrid_system_topic", "egst", "dashed")
	msg := naming.message(offender, "egst", "dashed")
}
