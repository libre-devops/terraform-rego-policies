package libredevops.naming.vm_scale_set

import rego.v1

_vmss(tf_type, name) := {"resource_changes": [{
	"address": sprintf("%s.%s", [tf_type, name]),
	"mode": "managed",
	"type": tf_type,
	"change": {"after": {"name": name}},
}]}

test_orchestrated_warns_on_bad_name if {
	count(warn) == 1 with input as _vmss("azurerm_orchestrated_virtual_machine_scale_set", "bad-name")
}

test_orchestrated_silent_on_good_name if {
	count(warn) == 0 with input as _vmss("azurerm_orchestrated_virtual_machine_scale_set", "vmssldouksprd001")
}

test_linux_uniform_warns_on_bad_name if {
	count(warn) == 1 with input as _vmss("azurerm_linux_virtual_machine_scale_set", "badname")
}

test_windows_uniform_silent_on_good_name if {
	count(warn) == 0 with input as _vmss("azurerm_windows_virtual_machine_scale_set", "vmssldouksprd001")
}
