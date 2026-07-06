# METADATA
# title: Service Bus topic subscription naming
# description: >-
#   azurerm_servicebus_subscription names should lead with the sbtsub- prefix and a purpose (sbtsub-security-incidents), per the Libre DevOps convention.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.servicebus_subscription

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_servicebus_subscription", "sbtsub", "prefix")
	msg := naming.message(offender, "sbtsub", "prefix")
}
