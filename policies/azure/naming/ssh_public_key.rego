# METADATA
# title: SSH public key naming
# description: >-
#   azurerm_ssh_public_key names should follow the Libre DevOps convention (sshkey-ldo-uks-prd-001). Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.naming.ssh_public_key

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_ssh_public_key", "sshkey", "dashed")
	msg := naming.message(offender, "sshkey", "dashed")
}
