# METADATA
# title: Bastion host naming
# description: >-
#   azurerm_bastion_host names should follow the Libre DevOps convention (bas-ldo-uks-prd-001). Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.naming.bastion_host

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_bastion_host", "bas", "dashed")
	msg := naming.message(offender, "bas", "dashed")
}
