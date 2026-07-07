# METADATA
# title: private dns resolver forwarding rule naming
# description: >-
#   azurerm_private_dns_resolver_forwarding_rule names should follow the Libre DevOps convention (rule-corp-to-onprem).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.private_dns_resolver_forwarding_rule

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_private_dns_resolver_forwarding_rule", "rule", "prefix")
	msg := naming.message(offender, "rule", "prefix")
}
