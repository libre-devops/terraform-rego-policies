# METADATA
# title: data collection rule naming
# description: >-
#   azurerm_monitor_data_collection_rule names should follow the Libre DevOps convention (dcr-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.data_collection_rule

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_monitor_data_collection_rule", "dcr", "dashed")
	msg := naming.message(offender, "dcr", "dashed")
}
