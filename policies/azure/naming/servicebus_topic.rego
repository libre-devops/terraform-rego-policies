# METADATA
# title: Service Bus topic naming
# description: >-
#   azurerm_servicebus_topic names should lead with the sbt- prefix and a purpose (sbt-platform-events), per the Libre DevOps convention.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.servicebus_topic

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_servicebus_topic", "sbt", "prefix")
	msg := naming.message(offender, "sbt", "prefix")
}
