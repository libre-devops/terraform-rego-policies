package libredevops.security.storage_public_blob_access

import rego.v1

test_warns_on_public_account_setting if {
	count(warn) == 1 with input as {"resource_changes": [{
		"address": "azurerm_storage_account.t", "mode": "managed", "type": "azurerm_storage_account",
		"change": {"after": {"name": "sat", "allow_nested_items_to_be_public": true}},
	}]}
}

test_warns_on_public_container if {
	count(warn) == 1 with input as {"resource_changes": [{
		"address": "azurerm_storage_container.t", "mode": "managed", "type": "azurerm_storage_container",
		"change": {"after": {"name": "data", "container_access_type": "blob"}},
	}]}
}

test_silent_on_private if {
	count(warn) == 0 with input as {"resource_changes": [
		{
			"address": "azurerm_storage_account.t", "mode": "managed", "type": "azurerm_storage_account",
			"change": {"after": {"name": "sat", "allow_nested_items_to_be_public": false}},
		},
		{
			"address": "azurerm_storage_container.t", "mode": "managed", "type": "azurerm_storage_container",
			"change": {"after": {"name": "data", "container_access_type": "private"}},
		},
	]}
}
