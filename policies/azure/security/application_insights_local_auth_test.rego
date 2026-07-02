package libredevops.security.application_insights_local_auth

import rego.v1

_appi(local_auth) := {"resource_changes": [{
	"address": "azurerm_application_insights.t",
	"mode": "managed",
	"type": "azurerm_application_insights",
	"change": {"after": {"name": "appi-t", "local_authentication_enabled": local_auth}},
}]}

test_warns_on_local_auth if {
	count(warn) == 1 with input as _appi(true)
}

test_silent_on_rbac_posture if {
	count(warn) == 0 with input as _appi(false)
}
