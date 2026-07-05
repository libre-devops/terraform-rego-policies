# METADATA
# title: AI Foundry hub naming (legacy)
# description: >-
#   azurerm_ai_foundry (the legacy Machine Learning hub-based Azure AI Foundry hub) names should follow
#   the Libre DevOps convention (aifh-ldo-uks-prd-001). Informational (warn): visible in the report but
#   it does not fail the build.
package libredevops.naming.ai_foundry

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_ai_foundry", "aifh", "dashed")
	msg := naming.message(offender, "aifh", "dashed")
}
