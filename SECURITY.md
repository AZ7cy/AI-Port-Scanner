# Security Policy

## Supported Versions

Security fixes are made on the `main` branch and included in the next release. Older releases do not receive fixes, so please update to the latest release.

## Reporting a Vulnerability

Please do not report security vulnerabilities in public issues, discussions, or pull requests.

Report them privately through GitHub:

1. Open the [Security tab](https://github.com/AZ7cy/AI-Port-Scanner/security) of this repository.
2. Click **Report a vulnerability**.
3. Describe the problem and how to reproduce it.

Direct link: <https://github.com/AZ7cy/AI-Port-Scanner/security/advisories/new>

Helpful details include:

- The affected version (release tag or commit hash), and whether you used `Cypher.exe` or ran from source
- Windows, Python, Nmap, and Ollama versions, if relevant
- The exact input or steps that trigger the problem, or a proof of concept
- The impact you expect, for example "command injection through the target field"

Remove real IP addresses, hostnames, and scan output from your report unless they are needed to reproduce the issue.

The maintainer will acknowledge your report, keep you informed while it is investigated, and credit you in the advisory if you wish. Please give the maintainer time to release a fix before you disclose the issue publicly.

## Scope

In scope are vulnerabilities in this project's code, for example:

- Injection of Nmap options or commands through the target, port, or settings fields
- Unescaped content in exported reports. Service banners, hostnames, and AI output come from untrusted sources.
- Unsafe handling of `scanner_settings.json` or other files the application reads
- Problems in the build configuration that affect the released `Cypher.exe`

Out of scope:

- Vulnerabilities in Nmap, Npcap, Ollama, or third-party Python packages. Report those to their maintainers.
- Findings about third-party systems that were discovered with this scanner
- Requests to scan systems or networks that you do not own or have permission to test

## Safe Use

- Download `Cypher.exe` only from this repository's [Releases](https://github.com/AZ7cy/AI-Port-Scanner/releases) page.
- Scan results and exported reports describe your network in detail. Store and share them carefully.
- AI analysis sends a summary of the scan results to the Ollama server configured in **Settings** over plain HTTP. Keep the default `localhost` unless you trust the remote server and the network path to it.
- Only scan systems and networks that you own or have explicit permission to test.
