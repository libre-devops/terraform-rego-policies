# METADATA
# title: Application Insights local authentication
# description: >-
#   With local authentication enabled, anyone holding the connection string or instrumentation key
#   can ingest telemetry; the RBAC posture (local auth off plus Monitoring Metrics Publisher grants)
#   removes that standing credential. Informational (warn): visible in the report but it does not
#   fail the build.
package libredevops.security.application_insights_local_auth

import data.lib.security
import rego.v1

warn contains msg if {
	some rc in security.managed(input.resource_changes, "azurerm_application_insights")
	rc.change.after.local_authentication_enabled == true
	msg := sprintf("security (info): %s accepts instrumentation-key ingestion; prefer local_authentication_enabled = false with Monitoring Metrics Publisher grants", [rc.address])
}
