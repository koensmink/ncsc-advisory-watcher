## Supported Versions
This project targets Python 3.11 and the latest GitHub Actions runner. Older versions may work but are not actively supported.

## Reporting a Vulnerability
**Please do not create a public issue for security reports.**  
Instead, contact the maintainer privately via the GitHub profile: https://github.com/koensmink

When reporting, please include (if possible):
- A clear description of the issue and potential impact
- Steps to reproduce or a proof-of-concept
- Affected files/lines (if known)
- Suggested remediation or mitigation ideas

## Scope
Reports relevant to this repository include (non-exhaustive):
- Command injection / arbitrary code execution
- Secrets leakage (tokens, keys) and credential handling
- Insecure parsing of external data (CSAF/RSS, CSV)
- Integrity of outputs (tamper risks)
- CI/CD (workflow) risks

## Out of Scope
- Vulnerabilities in third-party dependencies unless directly exploitable through this project
- Social engineering
- Physical attacks

## Coordinated Disclosure
If you believe the issue impacts others downstream, please mention this in your report. We follow a responsible disclosure approach: we will work with you on a fix and credit you upon request after a coordinated release.
