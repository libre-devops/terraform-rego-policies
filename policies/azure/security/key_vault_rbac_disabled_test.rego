package libredevops.security.key_vault_rbac_disabled

import rego.v1

_kv(rbac) := {"resource_changes": [{
	"address": "azurerm_key_vault.t",
	"mode": "managed",
	"type": "azurerm_key_vault",
	"change": {"after": {"name": "kv-t", "rbac_authorization_enabled": rbac}},
}]}

test_warns_on_access_policies if {
	count(warn) == 1 with input as _kv(false)
}

test_silent_on_rbac if {
	count(warn) == 0 with input as _kv(true)
}
