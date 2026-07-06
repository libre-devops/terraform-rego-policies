# METADATA
# title: Load balancer naming
# description: >-
#   azurerm_lb names should follow the Libre DevOps convention, with the prefix chosen by frontend
#   shape: a subnet frontend is an internal load balancer (lbi-), a public ip or public ip prefix
#   frontend is an external one (lbe-). Frontend ids referencing resources created in the same plan
#   are unknown at plan time, so the shape check also consults after_unknown. A load balancer whose
#   shape cannot be determined is skipped. Informational (warn): visible in the report but it does
#   not fail the build.
package libredevops.naming.lb

import data.lib.naming
import rego.v1

# A frontend field counts as set when it has a known non-empty value, or when it is marked unknown
# in the plan (a reference to a resource created in the same run).
_field_set(rc, field) if {
	some f in object.get(rc.change.after, "frontend_ip_configuration", [])
	v := object.get(f, field, "")
	is_string(v)
	v != ""
}

_field_set(rc, field) if {
	some f in object.get(object.get(rc.change, "after_unknown", {}), "frontend_ip_configuration", [])
	object.get(f, field, false) == true
}

_external(rc) if _field_set(rc, "public_ip_address_id")

_external(rc) if _field_set(rc, "public_ip_prefix_id")

# Azure forbids mixing private and public frontends on one load balancer; a subnet frontend decides
# internal.
_prefix(rc) := "lbi" if _field_set(rc, "subnet_id")

_prefix(rc) := "lbe" if {
	_external(rc)
	not _field_set(rc, "subnet_id")
}

warn contains msg if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "azurerm_lb"
	name := rc.change.after.name
	is_string(name)
	prefix := _prefix(rc)
	not naming.valid(name, prefix, "dashed")
	msg := sprintf(
		"naming (info): %s name %q does not match %s",
		[rc.address, name, naming.expected(prefix, "dashed")],
	)
}
