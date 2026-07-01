# METADATA
# title: Public IP naming
# description: >-
#   azurerm_public_ip names should follow the Libre DevOps convention (pip-ldo-uks-prd-001). Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.naming.public_ip

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_public_ip", "pip", "dashed")
	msg := naming.message(offender, "pip", "dashed")
}
