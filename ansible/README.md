# Ansible deployment

This playbook installs a two-node RillDNS deployment on Debian-family or
systemd-based Linux hosts. It downloads pinned RillDNS release bundles and the
official CoreDNS binary, creates the service account and state directories,
installs node-specific configuration, enables replication and timers, and
checks both health and metrics before finishing.

No real inventory, zone, or secret belongs in this public repository. The
provided `.gitignore` excludes the conventional local paths.

## First deployment

Requirements on the control machine:

- Ansible Core 2.15 or newer;
- SSH access to both hosts with privilege escalation;
- a published RillDNS release matching `rilldns_release_version`.

Start from the examples:

```sh
cd ansible
cp inventory.example.yml inventory.yml
mkdir -p local/zones
cp /path/to/your/example.test.zone local/zones/
ansible-vault create vault.yml
```

Put only the secret in `vault.yml`:

```yaml
vault_rilldns_tsig_secret: "a-base64-encoded-256-bit-secret"
```

Generate one if needed:

```sh
openssl rand -base64 32
```

Edit `inventory.yml` with the two hosts, their node roles and addresses,
recursive upstreams, authoritative zone names, release version, and primary
zone-file paths. All values in `inventory.example.yml` are reserved examples.

Review the plan and deploy:

```sh
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass --check --diff
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass
```

The playbook rolls through one node at a time. Its preflight assertions explain
missing variables before any host is changed. At completion it verifies the
local DNS health and management metrics endpoints.

## Checksums and private release mirrors

For production, set `rilldns_release_checksum` and
`rilldns_coredns_checksum` to Ansible checksum values such as
`sha256:<digest>`. You can point `rilldns_release_base_url` and
`rilldns_coredns_base_url` at an internal artifact mirror without changing the
role.

CoreDNS is pinned both here and in the local Compose environment. Dependabot
opens updates for the Compose image, and CI requires the version in
`roles/rilldns/defaults/main.yml` to match. Before deploying a CoreDNS update,
verify the upstream release for every deployed architecture, update the
production `rilldns_coredns_checksum`, run the playbook in check mode, and then
roll it out explicitly. Repository CI never deploys to DNS nodes.

## Browser UI

The browser UI is disabled by default. To enable it, set
`rilldns_ui_enabled: true` and provide the OIDC issuer, client credentials,
redirect URL, session key, and at least one immutable group or subject
allowlist. Preflight validation rejects incomplete UI configurations.

## Firewall and virtual IP

Firewall and VIP implementations differ across distributions and networks, so
the role deliberately does not guess. Before directing clients at the nodes,
allow DNS TCP/UDP 53 from trusted client networks, replication TCP/UDP 1054 and
verification TCP/UDP 1056 only between the two nodes, and metrics TCP 18053
only from trusted monitoring systems. Configure a VIP separately if desired.
