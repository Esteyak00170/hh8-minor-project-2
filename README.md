\# Mini IDS (Intrusion Detection System)



A lightweight, Python-based Intrusion Detection System built using \*\*Scapy\*\*. This tool monitors network traffic in real-time to detect specific attack signatures, focusing on ARP Spoofing, Nmap scans, and SQL Injection attempts.



\## 🚀 Features



\### 1. ARP Spoofing Detection

\* \*\*Mechanism:\*\* Maintains a dynamic table of IP-to-MAC address mappings.

\* \*\*Detection:\*\* Alerts immediately if a known IP address suddenly claims to have a different MAC address (a sign of a Man-in-the-Middle attack).



\### 2. SQL Injection (SQLi) Detection

\* \*\*Mechanism:\*\* Inspects the raw TCP payload of HTTP packets (Port 80).

\* \*\*Capabilities:\*\*

&nbsp;   \* Detects classic patterns: `UNION SELECT`, `' OR '1'='1`, `DROP TABLE`.

&nbsp;   \* Detects blind injection attempts: `SLEEP()`, `BENCHMARK()`.

&nbsp;   \* \*\*Smart Decoding:\*\* Automatically URL-decodes payloads (e.g., converts `%2D%2D` back to `--`) to catch obfuscated attacks.

&nbsp;   \* \*\*Noise Reduction:\*\* Ignored encrypted traffic (HTTPS/Port 443) to prevent false positives on binary data.



\### 3. Nmap Scan Detection

\* \*\*Mechanism:\*\* Analyzes TCP flags.

\* \*\*Detection:\*\* Specifically flags \*\*Xmas Scans\*\* (`FIN`, `PSH`, `URG` flags set), which are often used to evade simple firewalls.



---



\## 🛠️ Prerequisites



\* \*\*Python 3.x\*\*

\* \*\*Scapy\*\* library

\* \*\*Network Drivers:\*\*

&nbsp;   \* \*\*Windows:\*\* \[Npcap](https://npcap.com/) (Must be installed in "WinPcap API-compatible Mode").

&nbsp;   \* \*\*Linux:\*\* `libpcap` (usually pre-installed or via `sudo apt install libpcap-dev`).



---



\## 📦 Installation



1\.  \*\*Clone or Download\*\* this repository.

2\.  \*\*Install Python Dependencies:\*\*

&nbsp;   ```bash

&nbsp;   pip install scapy

&nbsp;   ```

3\.  \*\*Windows Users Only:\*\*

&nbsp;   Download and install \*\*Npcap\*\*. During installation, \*\*CHECK\*\* the box:  

&nbsp;   `\[x] Install Npcap in WinPcap API-compatible Mode`



---



\## 💻 Usage



Because this script requires direct access to the network card (raw sockets), it \*\*must\*\* be run with Administrator or Root privileges.



\### Windows

Open Command Prompt or PowerShell as \*\*Administrator\*\*:

```bash

python mini\_ids.py

