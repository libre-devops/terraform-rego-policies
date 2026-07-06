# METADATA
# title: Service Bus namespace naming
# description: >-
#   azurerm_servicebus_namespace names should follow the Libre DevOps convention (sb-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.servicebus_namespace

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_servicebus_namespace", "sb", "dashed")
	msg := naming.message(offender, "sb", "dashed")
}
