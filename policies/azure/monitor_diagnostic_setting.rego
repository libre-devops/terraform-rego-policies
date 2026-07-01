# METADATA
# title: Diagnostic setting naming
# description: >-
#   azurerm_monitor_diagnostic_setting names should follow the Libre DevOps convention
#   (diag-<target resource name>). Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.monitor_diagnostic_setting

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_monitor_diagnostic_setting", "diag", "prefix")
	msg := naming.message(offender, "diag", "prefix")
}
