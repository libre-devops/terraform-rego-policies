# METADATA
# title: AI Foundry hub project naming (legacy)
# description: >-
#   azurerm_ai_foundry_project (the legacy Machine Learning hub-based Azure AI Foundry project) names
#   should follow the Libre DevOps convention (aifp-ldo-uks-prd-001). Informational (warn): visible in
#   the report but it does not fail the build.
package libredevops.naming.ai_foundry_project

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_ai_foundry_project", "aifp", "dashed")
	msg := naming.message(offender, "aifp", "dashed")
}
