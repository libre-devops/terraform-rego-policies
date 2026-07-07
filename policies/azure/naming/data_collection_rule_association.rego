# METADATA
# title: Data collection rule association naming
# description: >-
#   azurerm_monitor_data_collection_rule_association names should lead with the dcra- prefix and a
#   purpose (dcra-linux-baseline), except the Azure-mandated literal configurationAccessEndpoint
#   for endpoint associations.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.data_collection_rule_association

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_monitor_data_collection_rule_association", "dcra", "prefix")
	offender.name != "configurationAccessEndpoint"
	msg := naming.message(offender, "dcra", "prefix")
}
