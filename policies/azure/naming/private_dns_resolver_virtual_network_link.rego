# METADATA
# title: private dns resolver virtual network link naming
# description: >-
#   azurerm_private_dns_resolver_virtual_network_link names should follow the Libre DevOps convention (link-vnet-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.private_dns_resolver_virtual_network_link

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_private_dns_resolver_virtual_network_link", "link", "prefix")
	msg := naming.message(offender, "link", "prefix")
}
