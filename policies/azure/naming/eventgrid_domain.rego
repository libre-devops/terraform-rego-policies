# METADATA
# title: Event Grid domain naming
# description: >-
#   azurerm_eventgrid_domain names should follow the Libre DevOps convention (evgd-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventgrid_domain

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventgrid_domain", "evgd", "dashed")
	msg := naming.message(offender, "evgd", "dashed")
}
