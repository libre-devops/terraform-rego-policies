# METADATA
# title: data collection endpoint naming
# description: >-
#   azurerm_monitor_data_collection_endpoint names should follow the Libre DevOps convention (dce-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.data_collection_endpoint

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_monitor_data_collection_endpoint", "dce", "dashed")
	msg := naming.message(offender, "dce", "dashed")
}
