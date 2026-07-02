<div align="center">

<a href="https://libredevops.org">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://libredevops.org/assets/libre-devops-white.png">
    <img alt="Libre DevOps" src="https://libredevops.org/assets/libre-devops-black.png" width="300">
  </picture>
</a>

# Terraform Rego Policies

Conftest/OPA (Rego) policies for Terraform plans: the Libre DevOps Azure naming convention plus
early-warning security checks. Azure (azurerm) today; the layout leaves room for more providers.

[![CI](https://github.com/libre-devops/terraform-rego-policies/actions/workflows/ci.yml/badge.svg)](https://github.com/libre-devops/terraform-rego-policies/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/libre-devops/terraform-rego-policies?sort=semver&label=release)](https://github.com/libre-devops/terraform-rego-policies/releases/latest)
[![License](https://img.shields.io/github/license/libre-devops/terraform-rego-policies)](./LICENSE)

</div>

---

## Overview

These are [Conftest](https://www.conftest.dev/) / [OPA](https://www.openpolicyagent.org/) policies
written in Rego and evaluated against a Terraform plan rendered to JSON
(`terraform show -json plan.bin > plan.json`). The plan JSON exposes the real resource attribute
values (`resource_changes[].change.after`), which is the right layer for naming conventions and for
catching configuration that scanners without plan context miss.

Every policy is **informational** (`warn`): findings surface in the report but never fail the build.
That is deliberate; see [Turning warnings into errors](#turning-warnings-into-errors) for the
escalation path.

## Layout

```
policies/
  lib/            shared helpers (naming construct, security predicates)
  azure/
    naming/       one policy per resource type, Libre DevOps naming convention
    security/     early-warning security checks
```

The directory per provider (`azure/`) is the extension point: policies for other providers get their
own tree with the same naming/security split.

## The policies

**Naming** (`libredevops.naming.*`): one small file per resource type, all driven by
[`lib/naming.rego`](./policies/lib/naming.rego), which encodes the
[Libre DevOps Azure naming convention](https://libredevops.org/docs/documents/azure-naming-convention/).
Names that are unknown at plan time are skipped (there is nothing to check yet). Built per module as
the module library is refactored, so the rego, the published convention, and the modules stay in
lockstep.

**Security** (`libredevops.security.*`): early-detection warnings for the obvious flaws, checked
where the plan actually shows them:

| Policy | Flags |
| --- | --- |
| `network_security_rule_any_any` | Inbound Allow from anywhere to every port (standalone rules and inline `security_rule` blocks) |
| `network_security_rule_management_ports` | SSH (22) or RDP (3389) exposed to the internet, including inside port ranges and lists |
| `role_assignment_broad_privilege` | Owner / User Access Administrator / RBAC Administrator granted at a whole subscription or management group (by role name or GUID) |
| `key_vault_rbac_disabled` | Vaults using access policies instead of RBAC authorization |
| `key_vault_purge_protection_disabled` | Vaults a purge away from losing soft-deleted material |
| `storage_account_insecure_transport` | Plaintext HTTP allowed, or a TLS 1.0/1.1 floor |
| `storage_public_blob_access` | Accounts permitting public nested items; containers with anonymous access |
| `application_insights_local_auth` | Components accepting instrumentation-key ingestion instead of the RBAC posture |

## Using the policies

The [`libre-devops/terraform-azure`](https://github.com/libre-devops/terraform-azure) action runs
these automatically against every plan (it clones this repo, `main` by default, and executes
`conftest test <plan>.json --policy policies --all-namespaces`). Locally:

```bash
terraform plan -out tfplan.bin && terraform show -json tfplan.bin > plan.json
conftest test plan.json --policy policies --all-namespaces
```

## Turning warnings into errors

Warnings never fail a build by default. Two escalation paths:

1. **Fail on any warning** without touching the policies: add `--fail-on-warn` to the conftest
   invocation. Coarse but immediate.

   ```bash
   conftest test plan.json --policy policies --all-namespaces --fail-on-warn
   ```

2. **Escalate specific policies**: fork or vendor this repo and change `warn contains msg if {` to
   `deny contains msg if {` in the policies you want to be blocking; conftest exits non-zero on any
   deny. This keeps the rest informational and is the right long-term shape for a policy you have
   finished rolling out.

## Developing

Run `just` to list recipes: `just fmt` / `just fmt-check` (Rego formatting), `just test` (the
hermetic unit tests; no cloud or real plan needed), and `just check plan.json` (evaluate against a
real plan JSON). CI runs formatting, the unit tests, and a smoke test of the full policy set against
[`test/fixtures/plan.json`](./test/fixtures/plan.json), so a syntax error or evaluation failure can
never reach a consumer build.

Releases are by tag (`just increment-release [patch|minor|major]`); the action tracks `main` by
default so new policies apply automatically, and consumers wanting stability pin a tag.
