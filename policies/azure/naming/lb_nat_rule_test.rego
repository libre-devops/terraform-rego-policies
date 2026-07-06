package libredevops.naming.lb_nat_rule

import rego.v1

_rule(name) := {"resource_changes": [{
	"address": sprintf("azurerm_lb_nat_rule.%s", [name]),
	"mode": "managed",
	"type": "azurerm_lb_nat_rule",
	"change": {"after": {"name": name}},
}]}

test_warns_on_missing_prefix if {
	count(warn) == 1 with input as _rule("ssh-admin")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _rule("rule-ssh-admin")
}
