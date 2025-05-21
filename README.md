
[+] Port Scanner Tool - Help Section

    [*] CEKA Port Scanner Tool
    [*] Developed by: CEKA
    [*] Version: 1.0

    Description:
      A high-performance port scanner tool that supports fast and full scanning
      (from 1 to 65535) using asynchronous programming (AsyncIO) for optimal speed.


    

        -h, --help              Show this help message and exit
        <host>                  Target IP or domain name (required)
        -r, --range             Port range to scan (e.g., 1-1024). Use 'all' for full scan.
        -t, --threads           Max concurrent tasks (default: 2000)
        -f, --format            Report format: json or txt (default: json)

        

    Requirements:
      - Python 3.7+
      - Install dependencies:
          pip install aiohttp colorama


    How to Run:
      - Interactive Mode:
          python ceka-ps.py
      - Full Scan on example.com:
          python ceka-ps.py example.com --range {1-1024, all} --threads 2000 --format {txt, json}

    Port Range Options:
      You can enter:
        - Custom range like: 1-1024
        - Full scan using: all or full
    

    Emergency Stop:
      Press 'q' at any time during the scan to stop it immediately.
    

    Save Report:
      After scanning, you can save results in JSON or TXT format.
      Reports are saved in the 'reports/' folder.

    Running on Termux (Android):
      pkg install python git
      pip install aiohttp colorama
      python ceka-ps.py