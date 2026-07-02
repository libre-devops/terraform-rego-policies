# METADATA
# title: NSG any-any rules
# description: >-
#   An inbound Allow rule from anywhere (*, 0.0.0.0/0, Internet, Any) to every port is an open door,
#   not a rule. Covers standalone azurerm_network_security_rule resources and inline security_rule
#   blocks. Informational (warn): visible in the report but it does not fail the build.
package libredevops.security.network_security_rule_any_any

import data.lib.security
import rego.v1

warn contains msg if {
	some entry in security.nsg_rules(input.resource_changes)
	security.allows_inbound(entry.rule)
	security.internet_source(entry.rule)

	# "Every port" means the rule covers both ends of the range: "*" and 0/1-65535 style ranges match,
	# a single service port does not.
	security.rule_ports_cover(entry.rule, 1)
	security.rule_ports_cover(entry.rule, 65535)
	msg := sprintf("security (info): %s allows inbound traffic from anywhere to every port (any-any)", [entry.address])
}
