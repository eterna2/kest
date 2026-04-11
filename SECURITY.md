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

Security issues should be reported securely so they can be addressed before public disclosure.

1. **Do not** file a public issue for a security vulnerability.
2. Please send a direct email or use the private vulnerability reporting feature on GitHub (if enabled on the repository) to discuss the vulnerability.
3. Be sure to include:
   - A description of the vulnerability and its potential impact.
   - A proof-of-concept (POC) or detailed steps to reproduce.
   - The version of Kest you tested against.

We will acknowledge receipt of the vulnerability and strive to send you regular updates about our progress until the issue is fixed.
