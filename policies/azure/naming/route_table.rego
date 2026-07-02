# METADATA
# title: Route table naming
# description: >-
#   azurerm_route_table names should follow the Libre DevOps convention (rt-ldo-uks-prd-001). Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.naming.route_table

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_route_table", "rt", "dashed")
	msg := naming.message(offender, "rt", "dashed")
}
