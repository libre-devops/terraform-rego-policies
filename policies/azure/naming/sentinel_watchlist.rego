# METADATA
# title: Sentinel watchlist naming
# description: >-
#   azurerm_sentinel_watchlist aliases should carry the wl- prefix over a purpose slug (wl-vip-users).
#   Informational (warn): visible in the report but it does not fail the build.
package libredevops.naming.sentinel_watchlist

import data.lib.naming
import rego.v1

warn contains msg if {
	some offender in naming.offenders(input.resource_changes, "azurerm_sentinel_watchlist", "wl", "prefix")
	msg := naming.message(offender, "wl", "prefix")
}
