# NetworkAnalyser

**NetworkAnalyser** is an automated network scanning and vulnerability analysis tool that integrates several security tools such as Nmap, Shodan, and VirusTotal. 
## Features

- **Dynamic Local Network Detection:** Automatically detects your local network range based on your IP address and subnet mask.
- **Network Scanning:** Uses Nmap (with options like `-sS -T4`) to scan hosts in the network.
- **API Integration:**
  - **Shodan:** Retrieves additional host information (for public IP addresses only).
  - **VirusTotal:** Analyzes potential threats based on VirusTotal data.
- **Vulnerability Assessment:** Performs a basic vulnerability analysis using Nmap banner data (e.g., identifying Apache on port 80 or OpenSSH on port 22) and suggests further checks.
- **Results Storage:** Saves scan results in a SQLite database for historical analysis.
- **HTML Report Generation:** Creates an HTML report using Jinja2 with key host data and detected vulnerabilities.
- **Automation & Scheduling:** Automatically runs scans at a defined interval (default is every 10 minutes) using the `schedule` library.

## Requirements

- **Python 3.x**
- **Nmap** – available from [nmap.org](https://nmap.org/)
- API Keys:
  - **Shodan API key** – available by signing up at [shodan.io](https://www.shodan.io/)
  - **VirusTotal API key** – available by signing up at [virustotal.com](https://www.virustotal.com/)
- Python libraries:
  - `python-nmap`
  - `shodan`
  - `netifaces`
  - `requests`
  - `jinja2`
  - `schedule`

## Installation

1. **Clone the repository:**

   ```bash
   git clone <REPOSITORY_URL>
   cd NetworkAnalyser
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python -m venv .venv
   # On Linux/MacOS:
   source .venv/bin/activate
   # On Windows:
   .venv\Scripts\activate
   ```

3. **Install dependencies:**

   Install the required packages:

   ```bash
   pip install python-nmap shodan netifaces requests jinja2 schedule
   ```

4. **Configure API keys and paths:**

   In the `NetworkAnalyser.py` file, replace the placeholders:
   - `YOUR_SHODAN_API_KEY`
   - `YOUR_VIRUSTOTAL_API_KEY`
   - `Path to nmap.exe`
   with your actual API keys and path to nmax.exe.

## Usage

To run the network scanner, execute the following command:

```bash
python NetworkAnalyser.py
```

During execution, the script will:
- Dynamically detect your local network range.
- Scan the network using Nmap.
- Retrieve data from Shodan and VirusTotal (for public IP addresses).
- Save the results into a SQLite database (`scan_results.db`).
- Generate an HTML report (`scan_report.html`).
- Automatically repeat the scan at the defined interval (default: every 10 minutes).

## Project Structure

- `NetworkAnalyser.py` – Main script for the project.
- `templates/` – Directory containing the HTML report template (`report_template.html`).  
  The template is automatically created if it does not exist.
- `scan_results.db` – SQLite database file storing scan results.
- `scan_report.html` – Generated HTML report with scan data and vulnerability findings.

## Future Enhancements

The project can be extended by:
- Integrating additional vulnerability assessment tools (e.g., OpenVAS, Nessus).
- Developing a user-friendly interface (web-based or desktop GUI).
- Implementing advanced vulnerability analysis with CVE databases.
- Adding notification systems (email, Slack) for new threat detections.
- Further automation and configurable scheduling options.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

Bartłomiej Dziura
