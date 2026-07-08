# METADATA
# title: Logic App connection references, not hardcoded ids
# description: >-
#   Action and trigger bodies must reference connections through the $connections parameter
#   (@parameters('$connections')[...]['connectionId']), never a literal Microsoft.Web/connections
#   resource id embedded in the body, per the Libre DevOps Logic App standard. Checked by decoding
#   the body and walking it for the literal connection path. Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.logicapp.no_hardcoded_connection_id

import data.lib.logicapp
import rego.v1

warn contains msg if {
	some t in logicapp.content_types
	some rc in logicapp.managed(input.resource_changes, t)
	body := logicapp.decoded_body(rc.change.after)
	some literal in _connection_literals(body)
	msg := sprintf("logic app standard (info): %s hardcodes a connection id (%q); reference @parameters('$connections')[...]['connectionId'] instead", [rc.address, literal])
}

# Any string anywhere in the body that embeds a literal connection resource id. Correct references
# go through @parameters('$connections') and never contain this path.
_connection_literals(body) := {s |
	walk(body, [_, s])
	is_string(s)
	contains(s, "/providers/Microsoft.Web/connections/")
}
