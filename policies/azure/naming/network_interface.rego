# METADATA
# title: Network interface naming
# description: >-
#   azurerm_network_interface names should carry the nic- prefix over the owning resource's name
#   (nic-vm-app-ldo-uks-prd-001). Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.network_interface

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_network_interface", "nic", "prefix")
	msg := naming.message(offender, "nic", "prefix")
}
