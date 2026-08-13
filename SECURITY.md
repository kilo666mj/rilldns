# Security policy

## Supported versions

Until the first stable release, security fixes are applied to the latest commit
on `main`. Older commits and private forks are not supported.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** form in the Security tab of the
repository. Do not open a public issue for suspected vulnerabilities or include
live DNS data, credentials, tokens, private keys, client identifiers, or query
logs in a report.

Include the affected component, reproduction steps, likely impact, and any
suggested mitigation. You should receive an acknowledgement within seven days.

## Security model

- The management API is designed for loopback access, not direct Internet
  exposure.
- The browser UI must sit behind TLS and requires a correctly configured OIDC
  provider.
- Zone transfers must use TSIG and peer-restricted firewall rules.
- Deployment secrets belong in root-owned files or service environment files,
  never in Git.
- The dnstap collector retains aggregate totals only; it must remain bound to
  loopback.
- Example deployment files are starting points, not a complete host-hardening
  or firewall policy.

Native DNSSEC signing and key lifecycle management are not currently provided.
