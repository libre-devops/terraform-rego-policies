# METADATA
# title: Logic App standard helpers
# description: >-
#   Shared building blocks for the Libre DevOps Logic App standard policies
#   (https://libredevops.org/docs/documents/azure-logic-app-standards). These layer on top of the
#   upstream terraform-rego-policies set: run conftest with both policy directories. Everything is
#   defensive about plan-time unknowns, a value that is not a known object/string/array is simply
#   not matched, so a computed value never breaks evaluation, it just is not checked yet.
package lib.logicapp

import rego.v1

# Consumption (Microsoft.Logic/workflows) and Standard (Microsoft.Web/sites) Logic App types.
logic_app_types := {"azurerm_logic_app_workflow", "azurerm_logic_app_standard"}

# Action and trigger content types whose body carries the workflow JSON.
content_types := {"azurerm_logic_app_action_custom", "azurerm_logic_app_trigger_custom"}

# Managed resource changes of tf_type whose after object is known at plan time.
managed(changes, tf_type) := {rc |
	some rc in changes
	rc.mode == "managed"
	rc.type == tf_type
	is_object(rc.change.after)
}

# All managed Logic App resource changes, either hosting model.
logic_apps(changes) := {rc |
	some t in logic_app_types
	some rc in managed(changes, t)
}

# Decoded content body. The body attribute is a JSON string; undefined when it is not a known
# string (computed at plan time), so there is nothing to check yet.
decoded_body(after) := obj if {
	is_string(after.body)
	obj := json.unmarshal(after.body)
}

# Every object anywhere inside a decoded body, the action itself and all nested actions (a Scope
# holds its children under .actions). walk visits the root and every descendant.
actions(body) := {v |
	walk(body, [_, v])
	is_object(v)
}
