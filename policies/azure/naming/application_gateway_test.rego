package libredevops.naming.application_gateway

import rego.v1

_agw(name) := {"resource_changes": [{
	"address": sprintf("azurerm_application_gateway.%s", [name]),
	"mode": "managed",
	"type": "azurerm_application_gateway",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _agw("badname")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _agw("agw-ldo-uks-prd-001")
}
