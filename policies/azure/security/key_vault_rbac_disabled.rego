# METADATA
# title: Key vault without RBAC authorization
# description: >-
#   Access-policy vaults manage data-plane access outside Azure RBAC: no PIM, no central review, easy
#   to accumulate stale grants. New vaults should use RBAC authorization. Informational (warn):
#   visible in the report but it does not fail the build.
package libredevops.security.key_vault_rbac_disabled

import data.lib.security
import rego.v1

warn contains msg if {
	some rc in security.managed(input.resource_changes, "azurerm_key_vault")
	rc.change.after.rbac_authorization_enabled == false
	msg := sprintf("security (info): %s uses access policies instead of RBAC authorization; prefer rbac_authorization_enabled = true", [rc.address])
}
