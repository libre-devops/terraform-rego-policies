package libredevops.naming.cognitive_account

import rego.v1

_c(kind, name) := {"resource_changes": [{
	"address": sprintf("azurerm_cognitive_account.%s", [name]),
	"mode": "managed",
	"type": "azurerm_cognitive_account",
	"change": {"after": {"name": name, "kind": kind}},
}]}

test_warns_on_bad_name if {
	count(warn) == 1 with input as _c("AIServices", "badname")
}

test_silent_on_good_aiservices_name if {
	count(warn) == 0 with input as _c("AIServices", "ais-ldo-uks-prd-001")
}

test_silent_on_good_openai_name if {
	count(warn) == 0 with input as _c("OpenAI", "oai-ldo-uks-prd-001")
}

test_silent_on_good_docintel_name if {
	count(warn) == 0 with input as _c("FormRecognizer", "docintel-ldo-uks-prd-001")
}

test_silent_on_good_generic_name if {
	count(warn) == 0 with input as _c("ContentSafety", "cog-ldo-uks-prd-001")
}

# An AIServices account named with the generic cog- prefix is the wrong prefix for its kind.
test_warns_on_wrong_prefix_for_kind if {
	count(warn) == 1 with input as _c("OpenAI", "cog-ldo-uks-prd-001")
}

test_silent_when_name_unknown if {
	count(warn) == 0 with input as {"resource_changes": [{
		"address": "azurerm_cognitive_account.this", "mode": "managed", "type": "azurerm_cognitive_account",
		"change": {"after": {"kind": "AIServices"}},
	}]}
}
