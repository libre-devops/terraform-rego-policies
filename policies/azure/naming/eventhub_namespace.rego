# METADATA
# title: Event Hubs namespace naming
# description: >-
#   azurerm_eventhub_namespace names should follow the Libre DevOps convention (evhns-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.eventhub_namespace

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_eventhub_namespace", "evhns", "dashed")
	msg := naming.message(offender, "evhns", "dashed")
}
