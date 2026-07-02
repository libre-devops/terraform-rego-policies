# METADATA
# title: Log Analytics workspace naming
# description: >-
#   azurerm_log_analytics_workspace names should follow the Libre DevOps convention (log-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.log_analytics_workspace

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_log_analytics_workspace", "log", "dashed")
	msg := naming.message(offender, "log", "dashed")
}
