# Contributing to Cypher AI Port Scanner

Thank you for your interest in improving the project. This guide explains how to report problems, set up a development environment, and submit changes.

By taking part in this project, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground Rules

- Test only against systems that you own or have explicit permission to scan, such as your own computer (`127.0.0.1`), a lab virtual machine, or [scanme.nmap.org](http://scanme.nmap.org/), which the Nmap project provides for occasional test scans.
- Do not post real IP addresses, hostnames, or scan reports in issues, pull requests, or commits unless you are sure they are safe to make public.
- Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues.

## Reporting Bugs and Requesting Features

Search the [existing issues](https://github.com/AZ7cy/AI-Port-Scanner/issues) first, then open a new one with the [issue templates](https://github.com/AZ7cy/AI-Port-Scanner/issues/new/choose).

## Development Setup

You need Windows, Python 3.10 or newer, and Nmap. Ollama is optional and only needed for AI analysis. See the [README](README.md#requirements) for installation details.

```powershell
git clone https://github.com/AZ7cy/AI-Port-Scanner.git
cd AI-Port-Scanner
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python ai_port_scanner.py
```

## Project Layout

The application is a single file, `ai_port_scanner.py`, divided into sections that start with a `# SECTION:` comment:

| Section | Contents |
| --- | --- |
| `scanner` | Nmap wrapper, basic scan profiles, and live output parsing |
| `socket_scanner` | Direct TCP socket scanner and pre-scan diagnostics |
| `advanced_scanner` | Advanced profiles, OS detection, vulnerability scripts, firewall and honeypot detection, and traceroute |
| `banner_grabber` | Service banner grabbing for open ports |
| `ai_analysis` | Ollama client and AI analysis of scan results |
| `anomaly_detector` | Rule-based risk and anomaly detection |
| `report_generator` | TXT, CSV, JSON, HTML, PDF, and DOCX exports |
| `logo` | Generated application logo |
| `settings_dialog` | Settings dialog and `scanner_settings.json` handling |
| `worker` | Background scan thread |
| `main_window` | Main PyQt6 window |
| `main` | Application entry point |

Put new code in the section it belongs to.

## Making Changes

1. Fork the repository and create a branch from `main`, for example `fix/csv-export` or `feature/udp-profile`.
2. Keep each pull request focused on a single change.
3. Follow the style of the surrounding code. Add type hints and a docstring to new functions and classes.
4. Treat everything the user types and everything a target sends back as untrusted:
   - Pass targets through `_validate_target()` before they reach Nmap.
   - Pass `subprocess` arguments as a list. Do not use `shell=True`.
   - Escape service banners, hostnames, and AI output before adding them to HTML, PDF, or DOCX reports.
5. Update `README.md` when you change features, requirements, or settings.
6. Add new dependencies to `requirements.txt` and check that the PyInstaller build still works.
7. Do not commit build output (`build/`, `dist/`, `*.exe`), `scanner_settings.json`, or exported reports. The `.gitignore` file already excludes them.

## Testing Your Changes

The project does not have an automated test suite yet. Before opening a pull request:

1. Check that the source compiles:

   ```powershell
   python -m py_compile ai_port_scanner.py
   ```

2. Run the application and scan an authorized target with each scan profile or mode that your change affects.
3. If you changed reports, export each affected format and open the result.
4. If you changed dependencies or packaging, build the executable and run it:

   ```powershell
   pip install pyinstaller
   python -m PyInstaller --clean --noconfirm Cypher.spec
   .\dist\Cypher.exe
   ```

## Commit Messages

Write short commit messages in the imperative mood that say what the change does, for example `Fix CSV export when no ports are open`.

## Pull Requests

Open your pull request against `main` and fill in the template. Describe what you tested, and on which Windows, Python, and Nmap versions. The maintainer will review it and may ask for changes.

## License

By contributing, you agree that your contributions are licensed under the project's [MIT License](LICENSE).
