# METADATA
# title: monitor private link scoped service naming
# description: >-
#   azurerm_monitor_private_link_scoped_service names should follow the Libre DevOps convention (scoped-law-central).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.monitor_private_link_scoped_service

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_monitor_private_link_scoped_service", "scoped", "prefix")
	msg := naming.message(offender, "scoped", "prefix")
}
