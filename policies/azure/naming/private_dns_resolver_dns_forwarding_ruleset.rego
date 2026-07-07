# METADATA
# title: private dns resolver dns forwarding ruleset naming
# description: >-
#   azurerm_private_dns_resolver_dns_forwarding_ruleset names should follow the Libre DevOps convention (dnsfrs-ldo-uks-prd-001).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.private_dns_resolver_dns_forwarding_ruleset

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_private_dns_resolver_dns_forwarding_ruleset", "dnsfrs", "dashed")
	msg := naming.message(offender, "dnsfrs", "dashed")
}
