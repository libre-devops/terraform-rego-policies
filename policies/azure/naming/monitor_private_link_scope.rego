# METADATA
# title: monitor private link scope naming
# description: >-
#   azurerm_monitor_private_link_scope names should follow the Libre DevOps convention (ampls-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.monitor_private_link_scope

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_monitor_private_link_scope", "ampls", "dashed")
	msg := naming.message(offender, "ampls", "dashed")
}
