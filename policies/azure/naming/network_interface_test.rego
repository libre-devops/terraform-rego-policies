package libredevops.naming.network_interface

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_network_interface.%s", [name]),
	"mode": "managed",
	"type": "azurerm_network_interface",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("nic-vm-app-ldo-uks-prd-001")
}
