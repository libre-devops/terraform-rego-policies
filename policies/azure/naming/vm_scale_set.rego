# METADATA
# title: Virtual machine scale set naming
# description: >-
#   Scale set names should follow the Libre DevOps no-dash convention (vmssldouksprd001), whichever
#   resource manages them: orchestrated (flexible), Linux uniform, or Windows uniform. Informational
#   (warn): visible in the report but it does not fail the build.
package libredevops.naming.vm_scale_set

import data.lib.naming
import rego.v1

_types := {
	"azurerm_orchestrated_virtual_machine_scale_set",
	"azurerm_linux_virtual_machine_scale_set",
	"azurerm_windows_virtual_machine_scale_set",
}

warn contains msg if {
	some tf_type in _types
	some offender in naming.offenders(input.resource_changes, tf_type, "vmss", "nodash")
	msg := naming.message(offender, "vmss", "nodash")
}
