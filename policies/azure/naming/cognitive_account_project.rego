# METADATA
# title: AI Foundry project naming (modern)
# description: >-
#   The modern, project-based Azure AI Foundry project (Microsoft.CognitiveServices/accounts/projects)
#   should follow the Libre DevOps convention (aifp-ldo-uks-prd-001). It is managed either as
#   azurerm_cognitive_account_project or, in the Libre DevOps ai-foundry-project module, as an
#   azapi_resource of that type. Informational (warn): visible in the report but it does not fail the
#   build.
package libredevops.naming.cognitive_account_project

import data.lib.naming
import rego.v1

# azurerm resource form.
warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_cognitive_account_project", "aifp", "dashed")
	msg := naming.message(offender, "aifp", "dashed")
}

# azapi resource form (the ai-foundry-project module manages projects via azapi_resource because the
# azurerm resource's delete races on an ETag If-Match precondition).
warn contains msg if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "azapi_resource"
	startswith(object.get(rc.change.after, "type", ""), "Microsoft.CognitiveServices/accounts/projects@")
	name := rc.change.after.name
	is_string(name)
	not naming.valid(name, "aifp", "dashed")
	msg := sprintf(
		"naming (info): %s name %q does not match %s",
		[rc.address, name, naming.expected("aifp", "dashed")],
	)
}
