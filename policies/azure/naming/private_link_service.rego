# METADATA
# title: private link service naming
# description: >-
#   azurerm_private_link_service names should follow the Libre DevOps convention (pl-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.private_link_service

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_private_link_service", "pl", "dashed")
	msg := naming.message(offender, "pl", "dashed")
}
