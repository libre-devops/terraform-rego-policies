# METADATA
# title: Private endpoint naming
# description: >-
#   azurerm_private_endpoint names should follow the Libre DevOps convention
#   (pep-<subresource>-<target resource name>). Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.private_endpoint

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_private_endpoint", "pep", "prefix")
	msg := naming.message(offender, "pep", "prefix")
}
