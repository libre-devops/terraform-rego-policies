# METADATA
# title: private dns resolver outbound endpoint naming
# description: >-
#   azurerm_private_dns_resolver_outbound_endpoint names should follow the Libre DevOps convention (out-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.private_dns_resolver_outbound_endpoint

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_private_dns_resolver_outbound_endpoint", "out", "dashed")
	msg := naming.message(offender, "out", "dashed")
}
