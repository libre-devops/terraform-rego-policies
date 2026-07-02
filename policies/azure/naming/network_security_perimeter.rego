# METADATA
# title: Network security perimeter naming
# description: >-
#   azurerm_network_security_perimeter names should follow the Libre DevOps convention (nsp-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.network_security_perimeter

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_network_security_perimeter", "nsp", "dashed")
	msg := naming.message(offender, "nsp", "dashed")
}
