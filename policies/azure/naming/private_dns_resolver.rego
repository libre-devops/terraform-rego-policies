# METADATA
# title: private dns resolver naming
# description: >-
#   azurerm_private_dns_resolver names should follow the Libre DevOps convention (dnspr-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.private_dns_resolver

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_private_dns_resolver", "dnspr", "dashed")
	msg := naming.message(offender, "dnspr", "dashed")
}
