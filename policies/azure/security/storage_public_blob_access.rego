# METADATA
# title: Storage public blob access
# description: >-
#   Anonymous blob access is the classic data-leak primitive: the account must not allow public
#   nested items, and containers should stay private. Informational (warn): visible in the report but
#   it does not fail the build.
package libredevops.security.storage_public_blob_access

import data.lib.security
import rego.v1

warn contains msg if {
	some rc in security.managed(input.resource_changes, "azurerm_storage_account")
	rc.change.after.allow_nested_items_to_be_public == true
	msg := sprintf("security (info): %s permits public blob containers; set allow_nested_items_to_be_public = false", [rc.address])
}

warn contains msg if {
	some rc in security.managed(input.resource_changes, "azurerm_storage_container")
	is_string(rc.change.after.container_access_type)
	rc.change.after.container_access_type != "private"
	msg := sprintf("security (info): %s grants anonymous %q access; container_access_type should be private", [rc.address, rc.change.after.container_access_type])
}
