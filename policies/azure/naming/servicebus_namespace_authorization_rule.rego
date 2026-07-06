# METADATA
# title: Service Bus namespace authorization rule naming
# description: >-
#   azurerm_servicebus_namespace_authorization_rule names should lead with the rule- prefix and a purpose (rule-legacy-sender), per the Libre DevOps convention.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.servicebus_namespace_authorization_rule

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_servicebus_namespace_authorization_rule", "rule", "prefix")
	msg := naming.message(offender, "rule", "prefix")
}
