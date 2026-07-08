package libredevops.logicapp.action_retry_policy

import rego.v1

_action(body) := {"resource_changes": [{
	"address": "azurerm_logic_app_action_custom.t",
	"mode": "managed",
	"type": "azurerm_logic_app_action_custom",
	"change": {"after": {"name": "HTTP_-_call", "body": json.marshal(body)}},
}]}

_http_no_retry := {"type": "Http", "inputs": {"method": "POST", "uri": "@parameters('x')"}}

_http_with_retry := {
	"type": "Http",
	"inputs": {"method": "POST", "uri": "@parameters('x')", "retryPolicy": {"type": "exponential", "count": 4}},
}

test_warns_on_top_level_http_without_retry if {
	count(warn) == 1 with input as _action(_http_no_retry)
}

test_silent_when_retry_present if {
	count(warn) == 0 with input as _action(_http_with_retry)
}

test_warns_on_nested_http_in_scope if {
	scope := {"type": "Scope", "actions": {"HTTP_-_call": _http_no_retry}}
	count(warn) == 1 with input as _action(scope)
}

test_silent_on_non_external_action if {
	count(warn) == 0 with input as _action({"type": "Compose", "inputs": {"x": 1}})
}

test_silent_on_apiconnection_with_retry if {
	apiconn := {"type": "ApiConnection", "inputs": {"host": {}, "retryPolicy": {"type": "none"}}}
	count(warn) == 0 with input as _action(apiconn)
}

test_warns_on_apiconnection_without_retry if {
	apiconn := {"type": "ApiConnection", "inputs": {"host": {}}}
	count(warn) == 1 with input as _action(apiconn)
}
