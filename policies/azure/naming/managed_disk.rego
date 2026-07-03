# METADATA
# title: Managed disk naming
# description: >-
#   azurerm_managed_disk names should be datadisk[NN]-<vm name> for data disks or osdisk[NN]-<vm name>
#   for OS disks (the numbering is optional; the Libre DevOps VM modules derive osdisk-<vm name>).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.managed_disk

import rego.v1

warn contains msg if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "azurerm_managed_disk"
	name := rc.change.after.name
	is_string(name)
	not regex.match(`^(datadisk|osdisk)[0-9]{0,3}-.+$`, name)
	msg := sprintf("naming (info): %s name %q does not match (datadisk|osdisk)[NN]-<vm name>", [rc.address, name])
}
