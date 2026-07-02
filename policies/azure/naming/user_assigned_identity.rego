# METADATA
# title: User assigned identity naming
# description: >-
#   azurerm_user_assigned_identity names should follow the Libre DevOps convention (id-ldo-uks-prd-001). Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.naming.user_assigned_identity

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_user_assigned_identity", "id", "dashed")
	msg := naming.message(offender, "id", "dashed")
}
