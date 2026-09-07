# Moving Cloudflare DNS record ownership from Terraform

Terraform and RillDNS must not manage the same Cloudflare DNS record. Complete
this migration one zone at a time, with no DNS-content change during handoff.

1. Run `terraform plan` and require a clean result.
2. Export the Terraform resource addresses and Cloudflare record IDs for the
   selected zone using `terraform state show` or `terraform show -json`.
3. Read the zone through `dns_cloudflare_list_records` and compare every name,
   type, value, TTL, proxy flag, comment, and tag with Terraform.
4. Back up the Terraform state and configuration repository.
5. Remove the selected DNS record resources from Terraform configuration.
6. Remove only those addresses from state with `terraform state rm`. This does
   not delete the remote Cloudflare records.
7. Run `terraform plan` again and require no proposed DNS record operations.
8. Use `dns_cloudflare_plan_changes` for a no-op plan, then acknowledge RillDNS
   as the zone's sole DNS-record writer in the operational change record.

Keep the Cloudflare zone, DNSSEC, account settings, rules, and token bootstrap
in Terraform. If ownership must return to Terraform, recreate configuration,
import the existing record IDs, and require a clean plan before disabling the
zone in RillDNS.

Never use `terraform apply` to resolve unexpected drift until the current owner
of the affected records has been established.
