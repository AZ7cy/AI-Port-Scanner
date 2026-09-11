# Cypher AI Port Scanner

A Windows-based graphical port scanning and network analysis tool built with Python and PyQt6.

## Features

- PyQt6 graphical user interface
- Nmap-based network scanning
- Direct TCP socket scanning
- Quick Scan using common/top ports
- Common port scanning
- Full TCP port scanning
- Service and version detection
- Operating system detection
- Firewall detection
- Honeypot detection
- Traceroute analysis
- Port and service risk/anomaly analysis
- Scan progress monitoring
- Ability to stop scans early
- Scan statistics
- Target validation
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
- Python 3.10 or newer
- Nmap
- Python packages listed in `requirements.txt`

### Python Dependencies

```text
PyQt6
python-nmap
requests
reportlab
python-docx

Installing Nmap

Nmap must be installed separately because python-nmap is a Python wrapper for Nmap and does not include the Nmap executable.

After installing Nmap, make sure nmap.exe is available through your system PATH.

Verify the installation with:

nmap --version
Installation

Clone the repository:

git clone https://github.com/AZ7cy/AI-Port-Scanner.git
cd AI-Port-Scanner

Create a virtual environment:

python -m venv .venv

Activate the virtual environment:

.venv\Scripts\Activate.ps1

Install the required Python packages:

python -m pip install --upgrade pip
pip install -r requirements.txt
Running the Scanner

Run the application with:

python ai_port_scanner.py

The application provides different scanning and analysis options through the graphical interface.

Some Nmap operations may require elevated privileges depending on the scan technique and Windows configuration.

Building the Windows Executable

The project includes a PyInstaller specification file:

Cypher.spec

Install PyInstaller if it is not already installed:

pip install pyinstaller

Build the executable:

python -m PyInstaller --clean --noconfirm Cypher.spec

The resulting executable will be placed in:

dist\Cypher.exe

The application icon is stored in:

icon.ico
Project Structure
AI-Port-Scanner/
├── ai_port_scanner.py
├── Cypher.spec
├── icon.ico
├── logo_512.png
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
└── screenshots/
Scanning Methods
Nmap Scanning

The scanner can use Nmap for network discovery, service detection, OS detection, traceroute, firewall analysis, and other advanced scanning operations.

Socket Scanning

Direct TCP socket scanning is also available. This provides a simpler alternative to Nmap for TCP connectivity checks.

Socket scanning does not provide all of the information available through Nmap, particularly for OS detection and certain service-detection capabilities.

Reports

Scan results can be exported in multiple formats:

TXT
CSV
JSON
HTML
PDF
DOCX

Reports can include scan information, discovered ports, services, statistics, and detected anomalies or warnings.

Security and Responsible Use

This software is intended for authorized security testing, network administration, learning, and defensive security research.

Only scan systems and networks that you own or have explicit permission to test.

Unauthorized port scanning or security testing may violate laws, regulations, contracts, or network policies.

The author is not responsible for misuse of this software.

Limitations

Results depend on:

Nmap availability and configuration
Network connectivity
Firewall rules
Target responses
Operating system permissions
Scan technique being used
Network filtering and packet loss

A scan result should not be treated as definitive proof of a security vulnerability.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Disclaimer

Cypher AI Port Scanner is provided for educational and authorized security-testing purposes.

Use it responsibly and only against systems for which you have permission.
