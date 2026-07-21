package libredevops.naming.cost_management_view

import rego.v1

_c(tf_type, name) := {"resource_changes": [{
	"address": sprintf("%s.%s", [tf_type, name]),
	"mode": "managed",
	"type": tf_type,
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("azurerm_subscription_cost_management_view", "myview")
}

test_silent_on_good_name if {
	count(warn) == 0 with input as _c("azurerm_subscription_cost_management_view", "cmviewldouksprd001")
}

test_covers_resource_group_scope if {
	count(warn) == 0 with input as _c("azurerm_resource_group_cost_management_view", "cmviewldouksprd002")
}
