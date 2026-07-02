# METADATA
# title: Storage account insecure transport
# description: >-
#   Storage accounts should require HTTPS and a modern TLS floor; plaintext HTTP or TLS 1.0/1.1
#   ingestion is interceptable. Informational (warn): visible in the report but it does not fail the
#   build.
package libredevops.security.storage_account_insecure_transport

import data.lib.security
import rego.v1

legacy_tls := {"TLS1_0", "TLS1_1"}

warn contains msg if {
	some rc in security.managed(input.resource_changes, "azurerm_storage_account")
	rc.change.after.https_traffic_only_enabled == false
	msg := sprintf("security (info): %s allows plaintext HTTP; set https_traffic_only_enabled = true", [rc.address])
}

warn contains msg if {
	some rc in security.managed(input.resource_changes, "azurerm_storage_account")
	is_string(rc.change.after.min_tls_version)
	rc.change.after.min_tls_version in legacy_tls
	msg := sprintf("security (info): %s accepts legacy TLS (%s); set min_tls_version = \"TLS1_2\"", [rc.address, rc.change.after.min_tls_version])
}
