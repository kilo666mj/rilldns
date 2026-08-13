# Publishing checklist

RillDNS was extracted from a private deployment repository. Publish the
sanitized working tree as a new repository with a fresh root commit. Do not
push or mirror the private repository's existing Git history: deleted content
and commit metadata remain recoverable from historical objects.

Before the first public push:

1. Run the tests, vet, Compose validation, and `git diff --check`.
2. Run a secret scanner against both the working tree and the intended public
   commit.
3. Search for real names, email addresses, hostnames, zones, IP addresses,
   identity-provider URLs, internal Git hosts, inventory, and operational
   incident details.
4. Confirm every address is loopback, an intentional public resolver, an RFC
   1918 ACL range, or a reserved documentation address.
5. Confirm example secrets are obvious placeholders and cannot authenticate.
6. Review screenshots visually for names, timestamps, zones, addresses, query
   data, browser chrome, and notifications.
7. Create the public root commit with the intended public author identity.
8. Enable private vulnerability reporting, Dependabot alerts, secret scanning,
   and branch protection on GitHub.

The repository target is `github.com/kilo666mj/rilldns`; the Go module path,
badges, and documentation already use that location.
