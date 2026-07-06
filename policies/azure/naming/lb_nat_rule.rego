# METADATA
# title: Load balancer inbound NAT rule naming
# description: >-
#   azurerm_lb_nat_rule names should lead with the rule- prefix and a purpose (rule-ssh-admin), per
#   the Libre DevOps convention for Microsoft.Network/loadBalancers/inboundNatRules. Informational
#   (warn): visible in the report but it does not fail the build.
package libredevops.naming.lb_nat_rule

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_lb_nat_rule", "rule", "prefix")
	msg := naming.message(offender, "rule", "prefix")
}
