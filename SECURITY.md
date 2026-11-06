# Security policy

kidctl holds a family's rules and a device-owner app on a child's phone: a
hole in it is a real problem for real families. Thank you for reporting one.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private
vulnerability reporting: the **Security** tab of this repository, then
**Report a vulnerability**. Do not open a public issue for a security
problem.

Include what you found, how to reproduce it and the version or commit
affected. You will get an answer as soon as the report has been looked at;
a fix is released before the details are made public.

## Supported versions

Fixes go into the latest commit of `main` (server image and agent release
built from it). There are no maintained older branches.

## Scope

In scope, among others: the server (device sync API, agent download, MCP
over OAuth and the legacy URL token, the GitOps write path, the abuse guard),
the agent (a way for the child to get around enforcement without a factory
reset counts), the release and update path of the agent.

Out of scope: a compromised server host, Kubernetes cluster or GitOps
repository; a leaked owner password, device token or release signing key;
a phone that was factory-reset (it is no longer managed: that is Android's
design); volumetric DDoS. The security design is in [docs/SERVER.md](docs/SERVER.md#security).
