package libredevops.naming.app_service_environment

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_app_service_environment_v3.%s", [name]),
	"mode": "managed",
	"type": "azurerm_app_service_environment_v3",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("my-ase")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("ase-ldo-uks-prd-001")
}
