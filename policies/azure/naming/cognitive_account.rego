# METADATA
# title: Cognitive account naming
# description: >-
#   azurerm_cognitive_account names should follow the Libre DevOps convention, with the prefix chosen
#   by kind: OpenAI -> oai-, AIServices (Azure AI Foundry) -> ais-, FormRecognizer (Document
#   Intelligence) -> docintel-, everything else -> cog-. Informational (warn): visible in the report
#   but it does not fail the build.
package libredevops.naming.cognitive_account

import data.lib.naming
import rego.v1

# Prefix slug per Cognitive Services account kind. Anything not called out uses the generic cog-.
_prefix(kind) := "oai" if kind == "OpenAI"

_prefix(kind) := "ais" if kind == "AIServices"

_prefix(kind) := "docintel" if kind == "FormRecognizer"

_prefix(kind) := "cog" if not kind in {"OpenAI", "AIServices", "FormRecognizer"}

warn contains msg if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "azurerm_cognitive_account"
	name := rc.change.after.name
	is_string(name)
	prefix := _prefix(object.get(rc.change.after, "kind", ""))
	not naming.valid(name, prefix, "dashed")
	msg := sprintf(
		"naming (info): %s name %q does not match %s",
		[rc.address, name, naming.expected(prefix, "dashed")],
	)
}
