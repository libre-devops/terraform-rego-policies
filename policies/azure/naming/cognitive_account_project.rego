# METADATA
# title: AI Foundry project naming
# description: >-
#   azurerm_cognitive_account_project (the modern, project-based Azure AI Foundry project) names should
#   follow the Libre DevOps convention (aifp-ldo-uks-prd-001). Informational (warn): visible in the
#   report but it does not fail the build.
package libredevops.naming.cognitive_account_project

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_cognitive_account_project", "aifp", "dashed")
	msg := naming.message(offender, "aifp", "dashed")
}
