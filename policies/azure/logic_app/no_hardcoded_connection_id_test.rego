package libredevops.logicapp.no_hardcoded_connection_id

import rego.v1

_content(tf_type, body) := {"resource_changes": [{
	"address": sprintf("%s.t", [tf_type]),
	"mode": "managed",
	"type": tf_type,
	"change": {"after": {"name": "n", "body": json.marshal(body)}},
}]}

_good := {"type": "ApiConnectionWebhook", "inputs": {"host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}}}}

_bad := {"type": "ApiConnectionWebhook", "inputs": {"host": {"connection": {"name": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Web/connections/conn-azuresentinel"}}}}

test_silent_on_parameters_reference if {
	count(warn) == 0 with input as _content("azurerm_logic_app_trigger_custom", _good)
}

test_warns_on_literal_connection_id_in_trigger if {
	count(warn) == 1 with input as _content("azurerm_logic_app_trigger_custom", _bad)
}

test_warns_on_literal_connection_id_in_action if {
	body := {"type": "ApiConnection", "inputs": {"host": {"connection": {"name": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/connections/servicenow"}}}}
	count(warn) == 1 with input as _content("azurerm_logic_app_action_custom", body)
}
