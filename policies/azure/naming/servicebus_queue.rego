# METADATA
# title: Service Bus queue naming
# description: >-
#   azurerm_servicebus_queue names should lead with the sbq- prefix and a purpose (sbq-incident-intake), per the Libre DevOps convention.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.servicebus_queue

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_servicebus_queue", "sbq", "prefix")
	msg := naming.message(offender, "sbq", "prefix")
}
