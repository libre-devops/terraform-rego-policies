package libredevops.naming.bastion_host

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_bastion_host.%s", [name]),
	"mode": "managed",
	"type": "azurerm_bastion_host",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("bas-ldo-uks-prd-001")
}
