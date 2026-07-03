package libredevops.naming.sentinel_watchlist

import rego.v1

_c(name) := {"resource_changes": [{
	"address": sprintf("azurerm_sentinel_watchlist.%s", [name]),
	"mode": "managed",
	"type": "azurerm_sentinel_watchlist",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("vip-users")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("wl-vip-users")
}
