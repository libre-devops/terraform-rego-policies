# METADATA
# title: Event hub consumer group naming
# description: >-
#   azurerm_eventhub_consumer_group names should lead with the cgrp- prefix and a purpose (cgrp-telemetry-processor), per the Libre DevOps convention for Microsoft.EventHub consumer groups.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventhub_consumer_group

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventhub_consumer_group", "cgrp", "prefix")
	msg := naming.message(offender, "cgrp", "prefix")
}
