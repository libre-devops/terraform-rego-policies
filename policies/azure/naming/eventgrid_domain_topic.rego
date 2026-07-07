# METADATA
# title: Event Grid domain topic naming
# description: >-
#   azurerm_eventgrid_domain_topic names should lead with the evgdt- prefix and a purpose (evgdt-orders), per the Libre DevOps convention for Microsoft.EventGrid domain topics.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventgrid_domain_topic

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventgrid_domain_topic", "evgdt", "prefix")
	msg := naming.message(offender, "evgdt", "prefix")
}
