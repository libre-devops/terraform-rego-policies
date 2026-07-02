# METADATA
# title: Key vault without purge protection
# description: >-
#   Without purge protection a deleted vault or secret can be permanently purged inside the retention
#   window, defeating soft delete; production vaults should enable it. Informational (warn): visible
#   in the report but it does not fail the build.
package libredevops.security.key_vault_purge_protection_disabled

import data.lib.security
import rego.v1

warn contains msg if {
	some rc in security.managed(input.resource_changes, "azurerm_key_vault")
	rc.change.after.purge_protection_enabled == false
	msg := sprintf("security (info): %s has purge protection disabled; enable it for vaults holding real material", [rc.address])
}
