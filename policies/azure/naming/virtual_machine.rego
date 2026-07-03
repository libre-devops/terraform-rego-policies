# METADATA
# title: Virtual machine naming
# description: >-
#   azurerm_linux_virtual_machine and azurerm_windows_virtual_machine resource names should follow the
#   purposed Libre DevOps convention (vm-app-ldo-uks-prd-001); the OS computer name is the flattened
#   no-dash form of the same parts, which the Libre DevOps VM modules derive automatically.
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.virtual_machine

import data.lib.naming
import rego.v1

vm_types := {"azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"}

warn contains msg if {
	some vm_type in vm_types
	some offender in naming.offenders(input.resource_changes, vm_type, "vm", "purposed")
	msg := naming.message(offender, "vm", "purposed")
}
