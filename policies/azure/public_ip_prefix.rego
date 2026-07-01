# METADATA
# title: Public IP Prefix naming
# description: >-
#   azurerm_public_ip_prefix names should follow the Libre DevOps convention (ippre-ldo-uks-prd-001). Informational (warn): visible in
#   the report but it does not fail the build.
package libredevops.naming.public_ip_prefix

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_public_ip_prefix", "ippre", "dashed")
	msg := naming.message(offender, "ippre", "dashed")
}
