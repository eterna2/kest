# Security Policy

## Supported Versions

Please upgrade to the latest versions for the most recent security patches. Currently, the active branch and the latest release tag are fully supported.

| Version | Supported          |
| ------- | ------------------ |
| >= 0.3.x| :white_check_mark: |
| < 0.3.0 | :x:                |

## Common Platform Enumeration (CPE)

If you are incorporating Kest into an SBOM (Software Bill of Materials) or configuring internal vulnerability scanners, use the following CPE v2.3 identifier structure:

```text
cpe:2.3:a:eterna2:kest:<VERSION>:*:*:*:*:*:*:*
```

Example for version `0.3.0`:
```text
cpe:2.3:a:eterna2:kest:0.3.0:*:*:*:*:*:*:*
```

## Reporting a Vulnerability

Security issues should be reported **privately** so they can be addressed before public disclosure.

1. **Do not** file a public GitHub issue for a security vulnerability.
2. Use **[GitHub Private Vulnerability Reporting](https://github.com/eterna2/kest/security/advisories/new)** to disclose the issue confidentially. This is the preferred reporting path.
3. Be sure to include:
   - A description of the vulnerability and its potential impact.
   - A proof-of-concept (POC) or detailed steps to reproduce.
   - The version of Kest you tested against.

We will acknowledge receipt and send regular updates until the issue is resolved.

> **Note**: Private vulnerability reporting must be enabled in the repository settings. If the link above is unavailable, please open a [GitHub Security Advisory](https://github.com/eterna2/kest/security/advisories) instead.
