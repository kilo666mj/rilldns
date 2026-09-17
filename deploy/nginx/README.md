# nginx example

These files show a documentation-only TLS reverse proxy for the rilldns control
plane:

- `dns.example.net-acme.conf` serves ACME HTTP-01 challenges and redirects
  other HTTP requests to HTTPS;
- `dns.example.net.conf` terminates TLS and sends requests to the active API,
  with the standby configured only as a transport fallback.

The example uses reserved addresses and names. Replace the certificate paths,
hostnames, addresses, listener policy, and trust boundary in private deployment
inventory. A reachable standby transport does not make it writable: retain the
application's active/read-only role checks and follow the fenced promotion
procedure in [the HA guide](../../docs/ha.md).

Validate the rendered configuration with `nginx -t` before reloading nginx.
