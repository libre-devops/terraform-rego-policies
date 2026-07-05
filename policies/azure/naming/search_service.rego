# METADATA
# title: Search service naming
# description: >-
#   azurerm_search_service names should follow the Libre DevOps convention (srch-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.search_service

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_search_service", "srch", "dashed")
	msg := naming.message(offender, "srch", "dashed")
}
