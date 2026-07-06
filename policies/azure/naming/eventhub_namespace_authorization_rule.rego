# METADATA
# title: Event Hubs namespace authorization rule naming
# description: >-
#   azurerm_eventhub_namespace_authorization_rule names should lead with the rule- prefix and a purpose (rule-telemetry-sender), per the Libre DevOps convention.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventhub_namespace_authorization_rule

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventhub_namespace_authorization_rule", "rule", "prefix")
	msg := naming.message(offender, "rule", "prefix")
}
