# METADATA
# title: Event Grid event subscription naming
# description: >-
#   azurerm_eventgrid_event_subscription names should lead with the evgs- prefix and a purpose (evgs-secret-rotation), per the Libre DevOps convention for Microsoft.EventGrid event subscriptions.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventgrid_event_subscription

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventgrid_event_subscription", "evgs", "prefix")
	msg := naming.message(offender, "evgs", "prefix")
}
