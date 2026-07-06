# METADATA
# title: Event Hubs schema group naming
# description: >-
#   azurerm_eventhub_namespace_schema_group names should lead with the schemas- prefix and a purpose (schemas-telemetry), per the Libre DevOps convention.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventhub_namespace_schema_group

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventhub_namespace_schema_group", "schemas", "prefix")
	msg := naming.message(offender, "schemas", "prefix")
}
