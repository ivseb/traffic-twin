# Contributing to traffic-twin

Thank you for your interest. The project is pre-alpha (phase 0): please open
an issue to discuss any non-trivial change before writing code.

## Clean-room rule (mandatory)

traffic-twin is an independent, clean-room implementation. Every contribution
must respect the following rule:

**Contributors must not read, copy, translate or port source code from any of
these projects:**

- Keploy
- Tusk
- Speedscale / proxymock
- Postman Insights / Akita
- Optic
- Levo.ai
- Akto
- WireMock
- Microcks
- Prism
- Hoverfly
- Mountebank
- GoReplay
- Greenmask

This applies to their source code, tests, fixtures and code snippets, whatever
their license. **Only public documentation** (user guides, API references,
published file-format specifications) may be used, for example to make the
exporters produce files those tools accept.

If you have previously studied the source code of one of these projects in
depth, say so in your pull request and avoid contributing to the overlapping
area. When in doubt, ask in an issue before writing code.

By submitting a contribution you confirm that it is your own work, written
under this rule.

## No real data

- Tests, fixtures, examples, screenshots and bug reports must contain
  **invented data only**: no real personal data, no real customer data, no
  captured production traffic, no real hostnames, tokens or credentials.
- Use clearly fictional values and reserved domains (`example.com`,
  `example.org`, `*.example`).
- Pull requests containing real data will be closed, and the data removed
  from history where possible.

## Development

Requirements: Go 1.25+, Node.js 24+, make.

```sh
make build   # UI, then bin/tt
make test    # Go tests
make lint    # gofmt check, go vet, staticcheck if installed
```

UI only:

```sh
cd ui
npm ci --ignore-scripts
npm run dev     # development server
npm run check   # type check
```

## Guidelines

- Code, comments, identifiers and commit messages in English.
- The Go core uses the standard library unless a dependency is clearly
  justified; SDKs under `sdk/<lang>/` have **zero runtime dependencies**.
  The project builds without cgo.
- Keep commits focused, with a clear message explaining *why*.
- Security-sensitive changes (sanitizer, policy, intake, gate, enrollment)
  need tests, including negative tests showing that disallowed values are
  dropped.
- Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the [Apache License 2.0](LICENSE).
