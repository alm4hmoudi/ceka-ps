import asyncio
import socket
import json
import os
from datetime import datetime
import sys
import signal
from colorama import Fore, Style, init
import aiohttp
import argparse

init(autoreset=True)

def show_help():
    print(Fore.CYAN + Style.BRIGHT + """
             \033[0;34m@@@@@@@@@@@@@@@@@                                 @@")                                                                          
	                                 \033[0;34m@@@@@@@@@                   @@")                                                                            
	                                         \033[0;34m@@@@@@@@           @@@")                                                                            
	                                               \033[0;34m@@@@@@      @@@")                                                                             
	                           \033[0;34m@@@@@@@@@@@@@@@@@@@@@@@@@@      @@@@@")                                                                           
	                 \033[0;34m@@@@@                              @      @@@@@")                                                                           
	           \033[0;34m@                            \033[0;34m@@@@@@@@@@@@@@       \033[0;34m@@@@@@@")                                                                       
	                                  @@@@@@@            \033[0;34m@   @ @@@@@  @@ ")                                                                      
	                             @@@@ @@        \033[0;34m@@@@@@@  @@@@ @@@@@@@   @@")                                                                     
	                          \033[0;34m@@    @@@    @        \033[0;34m@@@@@ @@@@@@@@@@@@     @@ ")                                                                 
	                      \033[0;34m@@       @@@    @@@@@@@@   \033[0;34m@@@@@@@@@@@@@@@@@@@@@@  @@")                                                                
	                    \033[0;34m@         @@@    @@@        \033[0;34m@@@@@@@@@@@@       @@@@@@@ @@")                                                              
	                             \033[0;37m@@@    @@@     \033[0;34m@@ @@@@@@ @@@ @@@@@        @@@@@@@")                                                             
	                            \033[0;37m@@@    @@@     \033[0;34m@@@@@@@@@@@@@@    @   @@@@@@   @@@@@ ")                                                           
	                           \033[0;37m@@@    @@@     \033[0;34m@ @@@@@@@  @@ @@@ @@@@@@@        @@@@@")                                                           
	                          \033[0;37m@@@    @@@         \033[0;34m@@@@@@           @@@         @@ @@@@@@ ")                                                       
	                         \033[0;37m@@@   @@@@           \033[0;34m@@@@@                        @@@  @@ ")                                                        
	                        \033[0;37m@@@   @@@@  @@@@@@@@@ \033[0;34m@@@@@         \033[0;31m@@@@@@@@@@@     \033[0;37m@@@ ")                                                           
	                       \033[0;37m@@@@   @@@   @@@@@@@@@ \033[0;34m@@@@@@@      \033[0;31m@@@@@@@@@@@@     \033[0;37m@@@")                                                            
	                        \033[0;37m@@@@   @@@             \033[0;34m@@@@@@@                     @@@  ")                                                           
	                          \033[0;37m@@@   @@@               \033[0;34m@@@@@@@                 @@@  ")                                                            
	                           \033[0;37m@@@   @@@@         @@@     \033[0;34m@@@@@@@@@@@@@@@@@  @@@   ")                                                            
	                            \033[0;37m@@@   @@@@         @@@   @@@        \033[0;34m@@@@@@@@@@@@   ")                                                            
	                             \033[0;37m@@@   @@@@         @@@   @@@             \033[0;34m@@@    @@ ")                                                           
	                              \033[0;37m@@@   @@@@         @@@   @@@            @@ \033[0;34m@@@    @@ ")                                                      
	                               \033[0;37m@@@   @@@@         @@@   @@@@         @@@   \033[0;34m@@     @ ")                                                       
	                                \033[0;37m@@@   @@@@         @@@@  @@@@       @@@      \033[0;34m@ ")                                                            
	                                 \033[0;37m@@@    @@@@@@@@@@  @@@@  @@@@     @@@        \033[0;34m@     @ ")                                                     
	                                  \033[0;37m@@@                             @@@          \033[0;34m@")                                                           
	                                   \033[0;37m@@@                          @@@@            \033[0;34m@ ")                                                         
	                                    \033[0;37m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")                                                                        
	                                                                                 \033[0;34m@")                                                         
	                                     \033[0;37m@@@@@@ @@@@@@ @@ @@@    @@@                 \033[0;34m@ ")                                                        
	                                     \033[0;37m@      @@@@   @@@@     @@ @@ ")                                                                         
	                                     \033[0;37m@@@@@@ @@@@@@ @@  @@  @@@@@@@")   
""")
    print(Fore.YELLOW + "[+] Port Scanner Tool - Help Section\n")
    print(Fore.GREEN + "[*] CEKA Port Scanner Tool")
    print(Fore.GREEN + "[*] Developed by: CEKA")
    print(Fore.GREEN + "[*] Version: 1.0\n")
    print(Fore.GREEN + "🔧 Description:")
    print("  A high-performance port scanner tool that supports fast and full scanning")
    print("  (from 1 to 65535) using asynchronous programming (AsyncIO) for optimal speed.")
    print()

    print("""

        -h, --help              Show this help message and exit
        <host>                  Target IP or domain name (required)
        -r, --range             Port range to scan (e.g., 1-1024). Use 'all' for full scan.
        -t, --threads           Max concurrent tasks (default: 2000)
        -f, --format            Report format: json or txt (default: json)

        """)

    print(Fore.GREEN + "📦 Requirements:")
    print("  - Python 3.7+")
    print("  - Install dependencies:")
    print("      pip install aiohttp colorama")
    print()

    print(Fore.GREEN + "🚀 How to Run:")
    print("  - Interactive Mode:")
    print("      python ceka-ps.py")
    print("  - Full Scan on example.com:")
    print("      python ceka-ps.py example.com --range {1-1024, all} --threads 2000 --format {txt, json}")

    print(Fore.GREEN + "🔢 Port Range Options:")
    print("  You can enter:")
    print("    - Custom range like: 1-1024")
    print("    - Full scan using: all or full")
    print()

    print(Fore.GREEN + "⏹️ Emergency Stop:")
    print("  Press 'q' at any time during the scan to stop it immediately.")
    print()

    print(Fore.GREEN + "💾 Save Report:")
    print("  After scanning, you can save results in JSON or TXT format.")
    print("  Reports are saved in the 'reports/' folder.")
    print()

    print(Fore.GREEN + "📱 Running on Termux (Android):")
    print("  pkg install python git")
    print("  pip install aiohttp colorama")
    print("  python ceka-ps.py")

    print(Fore.CYAN + "[*] Thank you for using ceka-ps tool!")


COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy"
}

CMS_SIGNATURES = {
    "WordPress": ["wp-content", "X-Pingback"],
    "Drupal": ["X-Drupal-Cache"],
    "Joomla": ["sitetools.php"],
    "Magento": ["X-Magento-*"],
    "Apache": ["Apache", "Apache.*Server"],
    "Nginx": ["nginx"],
    "ExpressJS": ["Express"],
    "IIS": ["Microsoft-IIS"]
}

SCAN_RESULTS = {}
STOP_SCAN = False

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    print(Fore.CYAN + Style.BRIGHT + """                                                                                                                                                                       
	             \033[0;34m@@@@@@@@@@@@@@@@@                                 @@")                                                                          
	                                 \033[0;34m@@@@@@@@@                   @@")                                                                            
	                                         \033[0;34m@@@@@@@@           @@@")                                                                            
	                                               \033[0;34m@@@@@@      @@@")                                                                             
	                           \033[0;34m@@@@@@@@@@@@@@@@@@@@@@@@@@      @@@@@")                                                                           
	                 \033[0;34m@@@@@                              @      @@@@@")                                                                           
	           \033[0;34m@                            \033[0;34m@@@@@@@@@@@@@@       \033[0;34m@@@@@@@")                                                                       
	                                  @@@@@@@            \033[0;34m@   @ @@@@@  @@ ")                                                                      
	                             @@@@ @@        \033[0;34m@@@@@@@  @@@@ @@@@@@@   @@")                                                                     
	                          \033[0;34m@@    @@@    @        \033[0;34m@@@@@ @@@@@@@@@@@@     @@ ")                                                                 
	                      \033[0;34m@@       @@@    @@@@@@@@   \033[0;34m@@@@@@@@@@@@@@@@@@@@@@  @@")                                                                
	                    \033[0;34m@         @@@    @@@        \033[0;34m@@@@@@@@@@@@       @@@@@@@ @@")                                                              
	                             \033[0;37m@@@    @@@     \033[0;34m@@ @@@@@@ @@@ @@@@@        @@@@@@@")                                                             
	                            \033[0;37m@@@    @@@     \033[0;34m@@@@@@@@@@@@@@    @   @@@@@@   @@@@@ ")                                                           
	                           \033[0;37m@@@    @@@     \033[0;34m@ @@@@@@@  @@ @@@ @@@@@@@        @@@@@")                                                           
	                          \033[0;37m@@@    @@@         \033[0;34m@@@@@@           @@@         @@ @@@@@@ ")                                                       
	                         \033[0;37m@@@   @@@@           \033[0;34m@@@@@                        @@@  @@ ")                                                        
	                        \033[0;37m@@@   @@@@  @@@@@@@@@ \033[0;34m@@@@@         \033[0;31m@@@@@@@@@@@     \033[0;37m@@@ ")                                                           
	                       \033[0;37m@@@@   @@@   @@@@@@@@@ \033[0;34m@@@@@@@      \033[0;31m@@@@@@@@@@@@     \033[0;37m@@@")                                                            
	                        \033[0;37m@@@@   @@@             \033[0;34m@@@@@@@                     @@@  ")                                                           
	                          \033[0;37m@@@   @@@               \033[0;34m@@@@@@@                 @@@  ")                                                            
	                           \033[0;37m@@@   @@@@         @@@     \033[0;34m@@@@@@@@@@@@@@@@@  @@@   ")                                                            
	                            \033[0;37m@@@   @@@@         @@@   @@@        \033[0;34m@@@@@@@@@@@@   ")                                                            
	                             \033[0;37m@@@   @@@@         @@@   @@@             \033[0;34m@@@    @@ ")                                                           
	                              \033[0;37m@@@   @@@@         @@@   @@@            @@ \033[0;34m@@@    @@ ")                                                      
	                               \033[0;37m@@@   @@@@         @@@   @@@@         @@@   \033[0;34m@@     @ ")                                                       
	                                \033[0;37m@@@   @@@@         @@@@  @@@@       @@@      \033[0;34m@ ")                                                            
	                                 \033[0;37m@@@    @@@@@@@@@@  @@@@  @@@@     @@@        \033[0;34m@     @ ")                                                     
	                                  \033[0;37m@@@                             @@@          \033[0;34m@")                                                           
	                                   \033[0;37m@@@                          @@@@            \033[0;34m@ ")                                                         
	                                    \033[0;37m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")                                                                        
	                                                                                 \033[0;34m@")                                                         
	                                     \033[0;37m@@@@@@ @@@@@@ @@ @@@    @@@                 \033[0;34m@ ")                                                        
	                                     \033[0;37m@      @@@@   @@@@     @@ @@ ")                                                                         
	                                     \033[0;37m@@@@@@ @@@@@@ @@  @@  @@@@@@@")
""")
    print(Fore.YELLOW + "[*] Fast Async Port Scanner - Full Scan & Report\n")

def emergency_stop(sig, frame):
    global STOP_SCAN
    STOP_SCAN = True
    print(f"\n{Fore.RED}[!] Emergency stop triggered. Waiting for tasks to finish...")

async def scan_port(ip, port):
    if STOP_SCAN:
        return
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=1
        )
        service = COMMON_SERVICES.get(port, "Unknown")
        print(f"{Fore.GREEN}[+] Port {port} is Open - {service}")
        SCAN_RESULTS[port] = {"status": "open", "service": service}
        writer.close()
        await writer.wait_closed()

        # If Port HTTP أو HTTPS، Start Advanced Scanning
        if port in [80, 443]:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{ip}"
            await analyze_web_server(url, port)

    except Exception as e:
        SCAN_RESULTS[port] = {"status": "closed"}

async def analyze_web_server(url, port):
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get(url, ssl=False) as resp:
                headers = dict(resp.headers)
                title = ""
                text = await resp.text()
                if "<title>" in text.lower():
                    start = text.find("<title>") + 7
                    end = text.find("</title>", start)
                    title = text[start:end].strip() if end != -1 else ""

                server = headers.get("Server", "")
                powered_by = headers.get("X-Powered-By", "")

                detected_cms = detect_cms(headers, title, text)

                print(f"{Fore.BLUE}[*] URL: {url}")
                print(f"{Fore.BLUE}[+] Title: {title}")
                print(f"{Fore.BLUE}[+] Server: {server}")
                print(f"{Fore.BLUE}[+] Powered-By: {powered_by}")
                print(f"{Fore.BLUE}[+] Detected CMS: {detected_cms}\n")

                SCAN_RESULTS[port]["web_info"] = {
                    "url": url,
                    "title": title,
                    "headers": headers,
                    "cms": detected_cms,
                    "server": server,
                    "powered_by": powered_by
                }

    except Exception as e:
        SCAN_RESULTS[port]["web_info"] = {"error": str(e)}

def detect_cms(headers, title, body):
    for cms, signs in CMS_SIGNATURES.items():
        if any(sign.lower() in title.lower() for sign in signs):
            return cms
        if any(sign.lower() in body.lower() for sign in signs):
            return cms
        if any(sign in headers for sign in signs):
            return cms
    return "Unknown"

def save_report(ip, format='json'):
    reports_dir = 'reports'
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{reports_dir}/ceka-ps_{ip}_{timestamp}"

    data = {
        "target": ip,
        "results": SCAN_RESULTS
    }

    if format == 'json':
        with open(f"{filename}.json", 'w') as f:
            json.dump(data, f, indent=4)
    elif format == 'txt':
        with open(f"{filename}.txt", 'w') as f:
            f.write(f"Fast Port Scan Report for {ip}\n")
            f.write("=" * 40 + "\n")
            for port, info in sorted(data["results"].items()):
                if info['status'] == 'open':
                    f.write(f"Port {port}: Open - {info.get('service', 'Unknown')}\n")
                    web_info = info.get("web_info")
                    if web_info and "error" not in web_info:
                        f.write(f"  URL: {web_info['url']}\n")
                        f.write(f"  Title: {web_info['title']}\n")
                        f.write(f"  CMS: {web_info['cms']}\n")
                        f.write(f"  Server: {web_info['server']}\n")
                        f.write(f"  Powered-By: {web_info['powered_by']}\n")
                    f.write("\n")
    print(f"\n{Fore.MAGENTA}[+] Report saved as {filename}.{format}")

async def main():

    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        show_help()
        return

    cli_mode = False
    host = None
    ports_input = "1-1024"
    max_tasks = 2000
    report_format = "json"

    if len(sys.argv) > 1:
        try:
            host = sys.argv[1]
            for i, arg in enumerate(sys.argv):
                if arg in ['-r', '--range'] and len(sys.argv) > i + 1:
                    ports_input = sys.argv[i + 1].lower()
                elif arg in ['-t', '--threads'] and len(sys.argv) > i + 1:
                    max_tasks = int(sys.argv[i + 1])
                elif arg in ['-f', '--format'] and len(sys.argv) > i + 1:
                    if sys.argv[i + 1].lower() in ['json', 'txt']:
                        report_format = sys.argv[i + 1].lower()
                    else:
                        print(f"{Fore.RED}[-] Invalid format. Use 'json' or 'txt'.")
                        return
            cli_mode = True
        except Exception as e:

            cli_mode = False


    if cli_mode and host:
        start_port, end_port = parse_port_range(ports_input)
    

    else:
        clear_screen()
        banner()

        choice = input(f"{Fore.CYAN}Do you need help? (y/n): ").strip().lower()
        if choice == 'y':
            show_help()
            input(f"\n{Fore.YELLOW}Press Enter to continue...")
            return

        host = input(f"{Fore.CYAN}Enter Host IP or Domain: ").strip()

        ports_input = input(f"{Fore.CYAN}Enter Port Range (e.g., 1-1024 or 'all' for full scan): ").strip().lower()
        start_port, end_port = parse_port_range(ports_input)

        max_tasks = int(input(f"{Fore.CYAN}Max concurrent tasks [Recommended: 2000]: ") or "2000")
        report_format = input(f"{Fore.CYAN}Save report as (json/txt) [default: json]: ").strip().lower() or "json"


    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"{Fore.RED}[-] Hostname could not be resolved.")
        return

    print(f"\n{Fore.YELLOW}[*] Target IP: {ip}")
    print(f"{Fore.YELLOW}[*] Starting fast async scan...\n")

    start_time = datetime.now()

    await start_mass_scan(ip, start_port, end_port, max_tasks)

    end_time = datetime.now()
    print(f"\n{Fore.CYAN}[!] Scan completed in {end_time - start_time}")

    save_report(ip, report_format)

    print(f"\n{Fore.GREEN}[+] Exiting the tool automatically. Thank you!\n")

def parse_port_range(ports_input):
    if ports_input.lower() in ['all', 'full']:
        print(f"{Fore.YELLOW}[+] Full port scan selected: 1-65535")
        return 1, 65535
    else:
        try:
            start, end = map(int, ports_input.split('-'))
            return start, end
        except ValueError:
            print(f"{Fore.RED}[-] Invalid port range format. Example: 1-1024")
            sys.exit(1)

async def start_mass_scan(ip, start_port, end_port, max_tasks):
    semaphore = asyncio.Semaphore(max_tasks)

    async def sem_scan(port):
        async with semaphore:
            await scan_port(ip, port)

    tasks = []
    for port in range(start_port, end_port + 1):
        if STOP_SCAN:
            break
        tasks.append(sem_scan(port))
    
    if tasks:
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    signal.signal(signal.SIGINT, emergency_stop)
    asyncio.run(main())