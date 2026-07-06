# METADATA
# title: Application gateway naming
# description: >-
#   azurerm_application_gateway names should follow the Libre DevOps convention
#   (agw-ldo-uks-prd-001). Informational (warn): visible in the report but it does not fail the
#   build.
package libredevops.naming.application_gateway

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_application_gateway", "agw", "dashed")
	msg := naming.message(offender, "agw", "dashed")
}
