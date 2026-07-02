# METADATA
# title: Cost anomaly alert naming
# description: >-
#   azurerm_cost_anomaly_alert names should follow the Libre DevOps convention (cmalert-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.cost_anomaly_alert

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_cost_anomaly_alert", "cmalert", "dashed")
	msg := naming.message(offender, "cmalert", "dashed")
}
