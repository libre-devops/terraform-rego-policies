package libredevops.naming.waf_policy

import rego.v1

_waf(name) := {"resource_changes": [{
	"address": sprintf("azurerm_web_application_firewall_policy.%s", [name]),
	"mode": "managed",
	"type": "azurerm_web_application_firewall_policy",
	"change": {"after": {"name": name}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _waf("badname")
}

test_silent_on_structured_name if {
	count(warn) == 0 with input as _waf("waf-ldo-uks-prd-001")
}

# The agfw module's derived default name (waf-<gateway name>) is accepted.
test_silent_on_derived_name if {
	count(warn) == 0 with input as _waf("waf-agw-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_web_application_firewall_policy.x", "mode": "managed",
		"type": "azurerm_web_application_firewall_policy",
		"change": {"after": {}, "after_unknown": {"name": true}},
	}]}
}
