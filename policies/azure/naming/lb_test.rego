package libredevops.naming.lb

import rego.v1

# Internal load balancer: a subnet frontend with a known id.
_fx_internal(name) := {"resource_changes": [{
	"address": sprintf("azurerm_lb.%s", [name]),
	"mode": "managed",
	"type": "azurerm_lb",
	"change": {"after": {
		"name": name,
		"frontend_ip_configuration": [{"name": "internal", "subnet_id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s"}],
	}},
}]}

# Internal load balancer whose subnet is created in the same plan: the id is only in after_unknown.
_fx_internal_unknown(name) := {"resource_changes": [{
	"address": sprintf("azurerm_lb.%s", [name]),
	"mode": "managed",
	"type": "azurerm_lb",
	"change": {
		"after": {"name": name, "frontend_ip_configuration": [{"name": "internal", "subnet_id": null}]},
		"after_unknown": {"frontend_ip_configuration": [{"subnet_id": true}]},
	},
}]}

# External load balancer: a public ip frontend.
_fx_external(name) := {"resource_changes": [{
	"address": sprintf("azurerm_lb.%s", [name]),
	"mode": "managed",
	"type": "azurerm_lb",
	"change": {"after": {
		"name": name,
		"frontend_ip_configuration": [{"name": "public", "public_ip_address_id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/p"}],
	}},
}]}

# External load balancer whose public ip is created in the same plan.
_fx_external_unknown(name) := {"resource_changes": [{
	"address": sprintf("azurerm_lb.%s", [name]),
	"mode": "managed",
	"type": "azurerm_lb",
	"change": {
		"after": {"name": name, "frontend_ip_configuration": [{"name": "public", "public_ip_address_id": null}]},
		"after_unknown": {"frontend_ip_configuration": [{"public_ip_address_id": true}]},
	},
}]}

test_internal_warns_on_bad_name if {
	count(warn) == 1 with input as _fx_internal("badname")
}

test_internal_silent_on_good_name if {
	count(warn) == 0 with input as _fx_internal("lbi-ldo-uks-prd-001")
}

test_internal_warns_on_external_prefix if {
	count(warn) == 1 with input as _fx_internal("lbe-ldo-uks-prd-001")
}

test_internal_unknown_subnet_still_checked if {
	count(warn) == 1 with input as _fx_internal_unknown("badname")
}

test_external_warns_on_bad_name if {
	count(warn) == 1 with input as _fx_external("lbi-ldo-uks-prd-001")
}

test_external_silent_on_good_name if {
	count(warn) == 0 with input as _fx_external("lbe-ldo-uks-prd-001")
}

test_external_unknown_pip_still_checked if {
	count(warn) == 1 with input as _fx_external_unknown("badname")
}

# A load balancer whose frontend shape cannot be determined is skipped.
test_undeterminable_shape_skipped if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_lb.x", "mode": "managed", "type": "azurerm_lb",
		"change": {"after": {"name": "badname", "frontend_ip_configuration": []}},
	}]}
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_lb.x", "mode": "managed", "type": "azurerm_lb",
		"change": {
			"after": {"frontend_ip_configuration": [{"subnet_id": "/s/x"}]},
			"after_unknown": {"name": true},
		},
	}]}
}
