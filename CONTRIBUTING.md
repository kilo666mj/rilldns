# Contributing

Thanks for helping improve RillDNS.

## Development

Install Go 1.26 or later, Docker with Compose, `dig`, and `curl`, then run:

```sh
make test
make up
make smoke
```

Before opening a pull request:

```sh
gofmt -w $(find cmd internal -name '*.go')
go test ./...
go vet ./...
git diff --check
```

Keep changes focused and add tests for new behavior. Public fixtures must use
reserved example domains (`example.com`, `example.net`, `example.org`, `.test`)
and documentation address blocks (`192.0.2.0/24`, `198.51.100.0/24`, or
`203.0.113.0/24`). Never submit real zones, hostnames, client data, credentials,
or private network inventories.

## Compatibility and security

Call out changes to DNS response behavior, zone publication, authentication,
replication, metrics, or service sandboxing in the pull request. Report
security issues privately as described in [SECURITY.md](SECURITY.md).
