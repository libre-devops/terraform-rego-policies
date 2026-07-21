# METADATA
# title: App Service Environment naming
# description: >-
#   azurerm_app_service_environment_v3 names should follow the Libre DevOps convention
#   (ase-ldo-uks-prd-001). Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.app_service_environment

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_app_service_environment_v3", "ase", "dashed")
	msg := naming.message(offender, "ase", "dashed")
}
