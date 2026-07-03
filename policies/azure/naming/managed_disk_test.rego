package libredevops.naming.managed_disk

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_managed_disk.%s", [name]),
	"mode": "managed",
	"type": "azurerm_managed_disk",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("badname")
}

test_silent_on_numbered_data_disk if {
	count(warn) == 0 with input as _c("datadisk01-vm-app-ldo-uks-prd-001")
}

test_silent_on_unnumbered_os_disk if {
	count(warn) == 0 with input as _c("osdisk-vm-app-ldo-uks-prd-001")
}
