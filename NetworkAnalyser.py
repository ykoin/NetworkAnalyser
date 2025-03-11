#!/usr/bin/env python3
import netifaces, ipaddress, nmap, shodan, requests, sqlite3, logging, json, time, schedule, concurrent.futures, os
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Config
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
NMAP_ARGS = "-sS -T4"
DB_FILE = "scan_results.db"
REPORT_FILE = "scan_report.html"
SCAN_INTERVAL_MINUTES = 10

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def get_local_network():
    try:
        gw = netifaces.gateways()['default'][netifaces.AF_INET][1]
        addr = netifaces.ifaddresses(gw)[netifaces.AF_INET][0]
        return str(ipaddress.IPv4Network(f"{addr['addr']}/{addr['netmask']}", strict=False))
    except Exception as e:
        logging.error(f"Error: {e}")
        return None

def scan_network(target, args):
    scanner = nmap.PortScanner(nmap_search_path=('Path to nmap.exe',))
    logging.info(f"Scanning {target} with {args}")
    scanner.scan(hosts=target, arguments=args)
    results = {}
    for host in scanner.all_hosts():
        info = {"hostname": scanner[host].hostname(), "state": scanner[host].state(), "protocols": {}}
        for proto in scanner[host].all_protocols():
            info["protocols"][proto] = {port: scanner[host][proto][port] for port in scanner[host][proto]}
        results[host] = info
    logging.info("Nmap scan complete.")
    return results

def query_shodan(api_key, ip):
    try:
        data = shodan.Shodan(api_key).host(ip)
        return {"ip": data.get("ip_str", ip),
                "organization": data.get("org", "N/A"),
                "os": data.get("os", "N/A"),
                "ports": [srv.get("port") for srv in data.get("data", [])]}
    except shodan.APIError as e:
        logging.error(f"Shodan error for {ip}: {e}")
        return {"error": str(e)}

def query_virustotal(api_key, ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            return r.json()
        else:
            logging.error(f"VT error for {ip}: {r.status_code} - {r.text}")
            return {"error": f"Status {r.status_code}"}
    except Exception as e:
        logging.error(f"VT exception for {ip}: {e}")
        return {"error": str(e)}

def vulnerability_scan(nmap_info):
    vulns = []
    for proto, ports in nmap_info.get("protocols", {}).items():
        for port, info in ports.items():
            prod = info.get("product", "").lower()
            if port == 80 and "apache" in prod:
                vulns.append("Potential Apache vulnerability")
            if port == 22 and "openssh" in prod:
                vulns.append("Potential OpenSSH vulnerability")
    return vulns

def save_to_database(results):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT, hostname TEXT, state TEXT,
                    nmap_data TEXT, shodan_data TEXT, virustotal_data TEXT,
                    vulnerabilities TEXT, scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    for host, data in results.items():
        c.execute('''INSERT INTO scan_results (host, hostname, state, nmap_data, shodan_data, virustotal_data, vulnerabilities)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (host, data["nmap"].get("hostname", ""), data["nmap"].get("state", ""),
                   json.dumps(data["nmap"]), json.dumps(data.get("shodan", {})),
                   json.dumps(data.get("virustotal", {})), json.dumps(data.get("vulnerabilities", []))))
    conn.commit()
    conn.close()
    logging.info("Results saved to SQLite.")

def generate_report(results):
    templates_dir = "templates"
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    template_path = os.path.join(templates_dir, "report_template.html")
    if not os.path.exists(template_path):
        with open(template_path, "w", encoding="utf-8") as f:
            f.write("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Network Scan Report</title>
</head>
<body>
    <h1>Network Scan Report</h1>
    <table border="1" cellspacing="0" cellpadding="5">
        <tr>
            <th>Host</th>
            <th>Hostname</th>
            <th>State</th>
            <th>Vulnerabilities</th>
        </tr>
        {% for host, data in results.items() %}
        <tr>
            <td>{{ host }}</td>
            <td>{{ data.nmap.hostname }}</td>
            <td>{{ data.nmap.state }}</td>
            <td>
                {% if data.vulnerabilities %}
                    <ul>
                    {% for vuln in data.vulnerabilities %}
                        <li>{{ vuln }}</li>
                    {% endfor %}
                    </ul>
                {% else %}
                    None
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
            """)
    env = Environment(loader=FileSystemLoader(templates_dir, encoding="utf-8"),
                      autoescape=select_autoescape(['html', 'xml']))
    template = env.get_template("report_template.html")
    rendered = template.render(results=results)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(rendered)
    logging.info(f"Report saved as {REPORT_FILE}")

def fetch_external_data(host, results, shodan_api, vt_api):
    info = results[host]
    if ipaddress.ip_address(host).is_private:
        logging.info(f"Private IP {host}, skipping external queries.")
        info["shodan"] = {"error": "Private IP"}
        info["virustotal"] = {"error": "Private IP"}
    else:
        logging.info(f"Fetching external data for {host}")
        info["shodan"] = query_shodan(shodan_api, host)
        info["virustotal"] = query_virustotal(vt_api, host)
    info["vulnerabilities"] = vulnerability_scan(info["nmap"])

def run_scan():
    local_network = get_local_network()
    if not local_network:
        logging.error("Local network not determined.")
        return
    logging.info(f"Local network: {local_network}")
    nmap_results = scan_network(local_network, NMAP_ARGS)
    results = {host: {"nmap": nmap_results[host]} for host in nmap_results}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_external_data, host, results, SHODAN_API_KEY, VIRUSTOTAL_API_KEY): host for host in results}
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error processing {futures[future]}: {e}")
    save_to_database(results)
    generate_report(results)
    logging.info("Scan complete.")

def scheduled_job():
    logging.info("Scheduled scan starting...")
    run_scan()

def main():
    run_scan()
    schedule.every(SCAN_INTERVAL_MINUTES).minutes.do(scheduled_job)
    logging.info(f"Scan scheduled every {SCAN_INTERVAL_MINUTES} minutes.")
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()
