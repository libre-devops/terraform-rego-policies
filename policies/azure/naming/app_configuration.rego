# METADATA
# title: App Configuration store naming
# description: >-
#   azurerm_app_configuration names should follow the Libre DevOps convention
#   (appcs-ldo-uks-prd-001). Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.app_configuration

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_app_configuration", "appcs", "dashed")
	msg := naming.message(offender, "appcs", "dashed")
}
