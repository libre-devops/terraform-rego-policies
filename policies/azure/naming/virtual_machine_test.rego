package libredevops.naming.virtual_machine

import rego.v1

_c(tf_type, name) := {"resource_changes": [{
	"address": sprintf("%s.%s", [tf_type, name]),
	"mode": "managed",
	"type": tf_type,
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_linux_name if {
	count(warn) == 1 with input as _c("azurerm_linux_virtual_machine", "badname")
}

test_warns_on_unpurposed_name if {
	count(warn) == 1 with input as _c("azurerm_windows_virtual_machine", "vm-ldo-uks-prd-001")
}

test_silent_on_good_linux_name if {
	count(warn) == 0 with input as _c("azurerm_linux_virtual_machine", "vm-app-ldo-uks-prd-001")
}

test_silent_on_good_windows_name if {
	count(warn) == 0 with input as _c("azurerm_windows_virtual_machine", "vm-wkr-ldo-uks-dev-002")
}
