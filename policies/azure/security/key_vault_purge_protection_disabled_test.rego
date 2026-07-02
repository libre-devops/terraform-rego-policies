package libredevops.security.key_vault_purge_protection_disabled

import rego.v1

_kv(pp) := {"resource_changes": [{
	"address": "azurerm_key_vault.t",
	"mode": "managed",
	"type": "azurerm_key_vault",
	"change": {"after": {"name": "kv-t", "purge_protection_enabled": pp}},
}]}

test_warns_when_disabled if {
	count(warn) == 1 with input as _kv(false)
}

test_silent_when_enabled if {
	count(warn) == 0 with input as _kv(true)
}
