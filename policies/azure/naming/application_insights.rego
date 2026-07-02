# METADATA
# title: Application Insights naming
# description: >-
#   azurerm_application_insights names should follow the Libre DevOps convention (appi-ldo-uks-prd-001). Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.naming.application_insights

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_application_insights", "appi", "dashed")
	msg := naming.message(offender, "appi", "dashed")
}
