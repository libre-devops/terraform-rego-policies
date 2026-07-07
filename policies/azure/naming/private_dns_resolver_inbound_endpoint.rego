# METADATA
# title: private dns resolver inbound endpoint naming
# description: >-
#   azurerm_private_dns_resolver_inbound_endpoint names should follow the Libre DevOps convention (in-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.private_dns_resolver_inbound_endpoint

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_private_dns_resolver_inbound_endpoint", "in", "dashed")
	msg := naming.message(offender, "in", "dashed")
}
