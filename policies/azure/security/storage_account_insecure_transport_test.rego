package libredevops.security.storage_account_insecure_transport

import rego.v1

_sa(https, tls) := {"resource_changes": [{
	"address": "azurerm_storage_account.t",
	"mode": "managed",
	"type": "azurerm_storage_account",
	"change": {"after": {"name": "sat", "https_traffic_only_enabled": https, "min_tls_version": tls}},
}]}

test_warns_on_http if {
	count(warn) == 1 with input as _sa(false, "TLS1_2")
}

test_warns_on_legacy_tls if {
	count(warn) == 1 with input as _sa(true, "TLS1_0")
}

test_warns_twice_on_both if {
	count(warn) == 2 with input as _sa(false, "TLS1_1")
}

test_silent_on_modern if {
	count(warn) == 0 with input as _sa(true, "TLS1_2")
}
