<p align="center">
  <img src="logo_512.png" alt="Cypher AI Port Scanner logo" width="160">
</p>

<h1 align="center">Cypher AI Port Scanner</h1>

<p align="center">
  A Windows-based graphical port scanning and network analysis tool built with Python and PyQt6, with optional local AI analysis through Ollama.
</p>

<p align="center">
  <img alt="Platform: Windows" src="https://img.shields.io/badge/platform-Windows-0078D6">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green"></a>
</p>

> **Authorized use only.** Only scan systems and networks that you own or have explicit permission to test. See [Security and Responsible Use](#security-and-responsible-use).

## Features

- PyQt6 graphical user interface
- Nmap-based network scanning with live per-port output
- Direct TCP socket scanning ("Full Detail" mode classifies every port as open, closed, or filtered)
- Quick Scan using common/top ports
- Common port scanning
- Full TCP port scanning
- Service and version detection
- Advanced Nmap profiles: aggressive version detection, service scripts, NSE vulnerability scripts, full comprehensive, SYN, and fragmented-packet scans
- Service banner grabbing on open ports
- Operating system detection
- Firewall detection
- Honeypot detection
- Traceroute analysis
- Port and service risk/anomaly analysis with a risk score
- AI analysis of scan results using a local Ollama model (optional)
- Scan progress monitoring
- Ability to stop scans early
- Scan statistics
- Target validation and a required authorization confirmation before scanning
- Export scan results to:
  - TXT
  - CSV
  - JSON
  - HTML
  - PDF
  - DOCX
- Cypher-themed application icon and interface

## Requirements

- Windows
- Python 3.10 or newer (only when running from source)
- [Nmap](https://nmap.org/download.html)
- [Ollama](https://ollama.com/download) (optional, only needed for AI analysis)
- Python packages listed in [`requirements.txt`](requirements.txt)

### Python Dependencies

| Package | Used for |
| --- | --- |
| `PyQt6` | Graphical interface |
| `python-nmap` | Nmap integration |
| `requests` | HTTP banner grabbing and the Ollama API |
| `reportlab` | PDF reports |
| `python-docx` | DOCX reports |
| `dnspython` | DNS banner grabbing (optional) |

## Installing Nmap

Nmap must be installed separately because `python-nmap` is a Python wrapper for Nmap and does not include the Nmap executable.

Download the Windows installer from [nmap.org](https://nmap.org/download.html). Keep the Npcap option selected during installation, because SYN, fragmented-packet, and OS-detection scans need it.

After installing Nmap, make sure `nmap.exe` is available through your system `PATH`. The scanner also checks the default install folders (`C:\Program Files (x86)\Nmap\` and `C:\Program Files\Nmap\`), and you can set a custom path in **Settings**.

Verify the installation with:

```powershell
nmap --version
```

## Setting Up AI Analysis (Optional)

AI analysis uses [Ollama](https://ollama.com) to run a language model on your own computer. Scans work without it; only the **AI Analysis** tab stays empty.

1. Install Ollama from [ollama.com/download](https://ollama.com/download).
2. Download the default model:

   ```powershell
   ollama pull llama3
   ```

3. Make sure Ollama is running. The Windows app runs it in the background; otherwise start it with `ollama serve`.
4. Start the scanner. It connects to `localhost:11434` by default. Click **⟳ Refresh** to reload the model list, and change the host, port, or default model in **Settings**.

After a scan, the scanner sends a summary of the open ports and services to the configured Ollama server and streams the response into the **AI Analysis** tab. With the default `localhost` setting, this data stays on your computer. If you configure a remote Ollama server, the summary is sent to it over plain HTTP.

## Installation

### Option 1: Download the executable

Download `Cypher.exe` from the [Releases](https://github.com/AZ7cy/AI-Port-Scanner/releases) page and run it. Nmap is still required; Ollama is optional.

### Option 2: Run from source

Clone the repository:

```powershell
git clone https://github.com/AZ7cy/AI-Port-Scanner.git
cd AI-Port-Scanner
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate the virtual environment:

```powershell
.venv\Scripts\Activate.ps1
```

Install the required Python packages:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Running the Scanner

From the project folder, run the launcher:

```powershell
.\run
```

In Command Prompt, use `run` instead. The launcher uses the project's `.venv` if one exists, and otherwise falls back to a Python interpreter from your `PATH`. You can also start the app directly:

```powershell
python ai_port_scanner.py
```

The application provides different scanning and analysis options through the graphical interface. Before scanning, you must confirm that you are authorized to scan the target.

Some Nmap operations require elevated privileges. Run the scanner as Administrator for SYN, fragmented-packet, and OS-detection scans, because they send raw packets.

## Settings

Open **Settings** to configure:

- Nmap binary path
- Ollama host and port
- Default AI model
- Default scan profile
- Socket scan threads and per-port timeout

Settings are saved to `scanner_settings.json` in the folder you start the scanner from. This file is excluded from Git by `.gitignore`.

## Building the Windows Executable

The project includes a PyInstaller specification file, `Cypher.spec`.

Install PyInstaller if it is not already installed:

```powershell
pip install pyinstaller
```

Build the executable:

```powershell
python -m PyInstaller --clean --noconfirm Cypher.spec
```

The resulting executable will be placed in `dist\Cypher.exe`. The application icon is stored in `icon.ico`.

Build output (`build/`, `dist/`, and `*.exe` files) is excluded from Git. To share a build, attach `Cypher.exe` to a [GitHub Release](https://github.com/AZ7cy/AI-Port-Scanner/releases) instead of committing it.

## Project Structure

```text
AI-Port-Scanner/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── config.yml
│   │   └── feature_request.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── ai_port_scanner.py       # Application source (single file)
├── run.cmd                  # Launcher: start with .\run
├── Cypher.spec              # PyInstaller build configuration
├── icon.ico                 # Executable icon
├── logo_512.png             # Project logo
├── requirements.txt         # Python dependencies
├── README.md
├── SECURITY.md
├── LICENSE
├── .gitattributes
└── .gitignore
```

## Scanning Methods

### Nmap Scanning

The scanner can use Nmap for network discovery, service detection, OS detection, traceroute, firewall analysis, and other advanced scanning operations.

### Socket Scanning

Direct TCP socket scanning is also available. This provides a simpler alternative to Nmap for TCP connectivity checks.

Socket scanning does not provide all of the information available through Nmap, particularly for OS detection and certain service-detection capabilities.

## Reports

Scan results can be exported in multiple formats:

- TXT
- CSV
- JSON
- HTML
- PDF
- DOCX

Reports can include scan information, discovered ports, services, statistics, detected anomalies or warnings, and AI analysis.

Reports describe the scanned network in detail. Store and share them carefully. Default export file names (`scan_report_*`, `scan_results_*`) are excluded from Git.

## Security and Responsible Use

This software is intended for authorized security testing, network administration, learning, and defensive security research.

Only scan systems and networks that you own or have explicit permission to test.

Unauthorized port scanning or security testing may violate laws, regulations, contracts, or network policies.

Banner grabbing opens extra connections to the open ports it finds. It sends an HTTP request to web ports and a `version.bind` query to DNS servers. On other ports it only reads what the service sends when the connection opens, such as an SSH, FTP, or SMTP greeting. It never tries to log in, but these connections can appear in the target's logs.

To report a vulnerability in the scanner itself, follow the [Security Policy](SECURITY.md).

The author is not responsible for misuse of this software.

## Limitations

Results depend on:

- Nmap availability and configuration
- Network connectivity
- Firewall rules
- Target responses
- Operating system permissions
- Scan technique being used
- Network filtering and packet loss

A scan result should not be treated as definitive proof of a security vulnerability.

AI analysis is generated by a language model and can be wrong. Verify its findings before acting on them.

## Contributing

Contributions are welcome through issues and pull requests. Please only scan systems you are authorized to test, and keep real IP addresses, hostnames, and scan output out of issues and pull requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

Cypher AI Port Scanner is provided for educational and authorized security-testing purposes.

Use it responsibly and only against systems for which you have permission.
