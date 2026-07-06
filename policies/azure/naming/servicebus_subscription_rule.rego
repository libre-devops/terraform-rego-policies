# METADATA
# title: Service Bus subscription rule naming
# description: >-
#   azurerm_servicebus_subscription_rule names should lead with the rule- prefix and a purpose (rule-high-severity-only), per the Libre DevOps convention.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.servicebus_subscription_rule

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_servicebus_subscription_rule", "rule", "prefix")
	msg := naming.message(offender, "rule", "prefix")
}
