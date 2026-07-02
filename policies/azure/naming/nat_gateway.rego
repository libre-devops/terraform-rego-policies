# METADATA
# title: NAT Gateway naming
# description: >-
#   azurerm_nat_gateway names should follow the Libre DevOps convention (ng-ldo-uks-prd-001). Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.naming.nat_gateway

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_nat_gateway", "ng", "dashed")
	msg := naming.message(offender, "ng", "dashed")
}
