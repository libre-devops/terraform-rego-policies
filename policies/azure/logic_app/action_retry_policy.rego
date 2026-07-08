# METADATA
# title: Logic App external call retry policy
# description: >-
#   Every external call in a workflow (an action of type Http or ApiConnection, at any nesting depth)
#   must set an explicit retryPolicy, an exponential retry for idempotent calls or type none for the
#   ones that must not repeat, never the silent default, per the Libre DevOps Logic App standard.
#   Checked by decoding the action_custom body and walking it. Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.logicapp.action_retry_policy

import data.lib.logicapp
import rego.v1

external_types := {"http", "apiconnection"}

warn contains msg if {
	some rc in logicapp.managed(input.resource_changes, "azurerm_logic_app_action_custom")
	body := logicapp.decoded_body(rc.change.after)
	some action in logicapp.actions(body)
	_is_external(action)
	not _has_retry(action)
	msg := sprintf("logic app standard (info): %s has an external call (type %q) with no explicit retryPolicy; set an exponential retry or type none", [rc.address, action.type])
}

_is_external(action) if {
	is_string(action.type)
	lower(action.type) in external_types
}

_has_retry(action) if action.inputs.retryPolicy
