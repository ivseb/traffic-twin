# Security policy

traffic-twin handles production traffic, so security reports are the highest
priority work on the project.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub's private vulnerability reporting:
go to the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- the affected component and version or commit;
- a description of the issue and its impact;
- steps to reproduce, using **invented data only** (never real traffic or real
  personal data);
- any suggested fix, if you have one.

We aim to acknowledge reports within 3 working days and to agree on a
disclosure timeline with the reporter. We will credit reporters who wish to be
credited.

## Supported versions

The project is pre-alpha. Only the latest commit on `main` receives fixes.

## Scope

In scope:

- the `tt` binary and all its subcommands (`core`, `egress`, `mock`, `export`);
- the SDKs under `sdk/`;
- the review UI and its HTTP API;
- the published container image and release artifacts (signatures, SBOMs).

Of particular interest, and treated as critical:

- any way for a real value to leave the application process (zone A) despite
  the policy, including sanitizer bypasses and differences between SDKs;
- any way for real or re-identifiable data to pass the publication gate;
- weaknesses in source enrollment, mTLS, policy signing or policy distribution;
- fail-open behaviour (a source falling back to a more permissive policy).

Out of scope:

- the demo application under `demo/`, unless the issue also affects the
  components above;
- vulnerabilities in third-party dependencies that are not exploitable through
  traffic-twin (please report them upstream);
- deployments that knowingly disable documented safeguards (for example an
  explicitly enabled MITM proxy mode).
