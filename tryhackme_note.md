# TryHackMe Cybersecurity Notes

> A consolidated reference for security learning and authorized lab work. Commands that scan, authenticate, exploit, or capture traffic should be used only against systems for which you have explicit permission.

## Contents

- [Reconnaissance and OSINT](#reconnaissance-and-osint)
- [Linux and Windows Fundamentals](#linux-and-windows-fundamentals)
- [Processes, Services, and Packages](#processes-services-and-packages)
- [Password Attacks and Wordlists](#password-attacks-and-wordlists)
- [Digital Forensics and Incident Response](#digital-forensics-and-incident-response)
- [Logs and SIEM](#logs-and-siem)
- [Firewalls and IDS](#firewalls-and-ids)
- [Vulnerability Management](#vulnerability-management)
- [Malware Analysis Tooling](#malware-analysis-tooling)
- [Security Models](#security-models)
- [Network Scanning with Nmap](#network-scanning-with-nmap)
- [Penetration Testing](#penetration-testing)
- [Wireless Security](#wireless-security)
- [Protocols and Network Services](#protocols-and-network-services)
- [Traffic Analysis and TLS](#traffic-analysis-and-tls)
- [Web Enumeration and Content Discovery](#web-enumeration-and-content-discovery)
- [Modern Web Stacks](#modern-web-stacks)
- [Web Server Enumeration](#web-server-enumeration)
- [Web Application Vulnerabilities](#web-application-vulnerabilities)
- [API Testing](#api-testing)
- [Vulnerability Databases and Scanners](#vulnerability-databases-and-scanners)

## Reconnaissance and OSINT

### Finding hidden content

Manual checks should come before automated enumeration:

- `robots.txt`
- `sitemap.xml`
- HTML source, JavaScript files, comments, and linked resources
- Common administrative and backup paths

Example directory enumeration:

```bash
dirb http://TARGET/
gobuster dir -u http://TARGET/ -w /path/to/wordlist.txt
ffuf -u http://TARGET/FUZZ -w /path/to/wordlist.txt
```

### Useful public sources

- **Shodan** — Internet-connected service and device search.
- **VirusTotal** — File, URL, domain, and IP reputation data.
- **CVE databases** — Public vulnerability identifiers and descriptions.
- **GitHub** — Public source code, commit history, and accidentally exposed secrets.
- **Manual pages** — Local command documentation; for example, `man nc`.

### Passive reconnaissance

Passive reconnaissance collects information without directly interacting with the target service where possible.

#### WHOIS and RDAP

- **WHOIS** is a legacy registration lookup protocol, traditionally using TCP port 43. The commonly cited WHOIS specification is RFC 3912.
- **RDAP** (Registration Data Access Protocol) is the modern, HTTP-based alternative. It can be queried with a browser or tools such as `curl`.

#### DNS lookups

```bash
nslookup -type=A example.com
dig example.com A
dig @1.1.1.1 example.com AAAA
```

Common record types:

| Record | Meaning |
| --- | --- |
| `A` | IPv4 address |
| `AAAA` | IPv6 address |
| `CNAME` | Alias for another DNS name |
| `MX` | Mail-exchange server |
| `NS` | Authoritative name server |
| `SOA` | Start of Authority record |
| `TXT` | Arbitrary text, often including SPF or verification data |

Public resolvers such as `1.1.1.1` can reduce reliance on an ISP resolver, but they do not make DNS queries anonymous. DNS over HTTPS (DoH) and DNS over TLS (DoT) encrypt the connection to the resolver.

Useful sources for subdomain discovery include certificate-transparency logs at [crt.sh](https://crt.sh), DNS history services, and Shodan. Always verify discovered names because certificates and historical records can be stale.

#### Search-engine reconnaissance

Examples of search operators:

```text
site:example.com
site:example.com inurl:admin
site:example.com filetype:pdf
site:example.com intext:password
site:example.com intitle:admin
```

Other useful sources include Wappalyzer, the Internet Archive's Wayback Machine, public GitHub repositories, and cloud storage such as Amazon S3. Treat any credentials discovered during OSINT as sensitive and report them through the appropriate channel.

### Active reconnaissance

Active reconnaissance sends traffic to the target and may be logged.

#### `ping`

```bash
ping -c 4 TARGET_IP
ping -4 -c 4 TARGET_IP
ping -6 -c 4 TARGET_HOSTNAME
```

Ping tests reachability. TTL values can provide a rough operating-system clue—Linux systems often start with 64 and Windows systems often start with 128—but routing, configuration, and virtualization make this inference unreliable.

#### `traceroute` and `mtr`

```bash
traceroute TARGET
traceroute -T -p 443 TARGET
traceroute -I TARGET
mtr TARGET
```

On many Linux systems, `traceroute` uses UDP probes by default; `-T` uses TCP and `-I` uses ICMP. `mtr` combines repeated traceroute measurements with ping-style statistics.

#### Banner grabbing and basic connectivity

Telnet is an unencrypted legacy protocol on TCP port 23. It can be useful in a lab for testing a plain-text service or inspecting a banner, but it should not be used for real authentication. Prefer `nc`, `ncat --ssl`, or `openssl s_client` when encryption is required.

```bash
nc -nv TARGET_IP PORT
ncat --ssl TARGET_IP 443
openssl s_client -connect TARGET:443 -servername TARGET
```

## Linux and Windows Fundamentals

### Linux fundamentals

Linux was first released publicly in 1991. Frequently used commands include:

| Command | Purpose |
| --- | --- |
| `echo` | Print text or variable values |
| `whoami` | Display the current user |
| `ls`, `ls -l` | List files; `-l` shows detailed permissions |
| `cat` | Print a file |
| `cd`, `pwd` | Change directory; print the current directory |
| `find` | Search for files and directories |
| `wc` | Count lines, words, or bytes |
| `grep -R` | Recursively search text |
| `touch` | Create a file or update its timestamp |
| `mkdir` | Create a directory |
| `rm` | Remove files; use carefully |
| `cp`, `mv` | Copy or move files |
| `file` | Identify a file's type |
| `su -` | Start a login shell as another user |

#### Permissions

Permissions are shown for the **owner**, **group**, and **others**. `r`, `w`, and `x` mean read, write, and execute. For example:

```bash
chmod 750 script.sh
```

This grants the owner `rwx`, the group `r-x`, and everyone else no permissions. Numeric permissions use `r=4`, `w=2`, and `x=1`.

#### Shell operators

| Operator | Meaning |
| --- | --- |
| `&` | Run a command in the background |
| `&&` | Run the next command only if the previous one succeeds |
| `\|` | Pipe one command's output into another command's input |
| `>` | Redirect output and overwrite the destination |
| `>>` | Redirect output and append to the destination |

#### Important directories

- `/etc` — System-wide configuration. `/etc/passwd` contains account metadata; password hashes are normally stored in the root-readable `/etc/shadow` file, not in `/etc/passwd`.
- `/var` — Variable data, including logs, caches, queues, and application data.
- `/root` — Home directory of the `root` account.
- `/tmp` — Temporary files, commonly writable by multiple users. Do not assume that files there are trustworthy.

#### Editors and file transfer

- `nano` — Exit with `Ctrl+X`; it prompts to save changes.
- `vim` — Modal editor with extensive customization.
- `wget` — Download over HTTP(S):

  ```bash
  wget https://example.com/file.txt
  ```

- `scp` — Copy files over SSH:

  ```bash
  scp important.txt ubuntu@192.168.1.30:/home/ubuntu/transferred.txt
  ```

- Python's built-in HTTP server — Serve the current directory in a lab:

  ```bash
  python3 -m http.server 8000
  wget http://MACHINE_IP:8000/file.txt
  ```

### Windows fundamentals

Important Windows concepts include users and groups, NTFS permissions, services, scheduled tasks, the Registry, PowerShell, and Event Viewer. When investigating a Windows host, record the operating-system version, logged-on users, running services, network connections, scheduled tasks, and relevant event logs.

## Processes, Services, and Packages

### Processes and jobs

```bash
ps aux
kill PID
systemctl status SERVICE
systemctl start SERVICE
```

`ps aux` shows processes and their owners. `Ctrl+Z` suspends the foreground job; `bg` resumes it in the background and `fg` brings a background job to the foreground. `systemctl` manages services through systemd on systems that use it.

### Scheduled tasks

Cron jobs are scheduled with crontab files. Edit the current user's crontab with:

```bash
crontab -e
```

Review permissions and ownership carefully when assessing scheduled tasks; a writable script executed by a privileged cron job can create a serious escalation path.

### Package management

On Debian-based systems, APT configuration and repository information are stored under `/etc/apt/`. Use the distribution's package manager rather than downloading untrusted packages manually.

## Password Attacks and Wordlists

Use password testing only with explicit authorization and respect rate limits and account-lockout controls.

- **John the Ripper** and **Hashcat** — Offline cracking of password hashes.
- **Hydra**, **Medusa**, and **Ncrack** — Online authentication testing against supported services.
- **NetExec** (formerly CrackMapExec) — Authentication and enumeration workflows for Windows and Active Directory environments.
- **Burp Suite Intruder** — Controlled testing of web authentication parameters.
- **Aircrack-ng** — Wireless capture analysis and key recovery in authorized labs.
- **Crunch** — Generates wordlists from a defined pattern; generated lists can become very large.

Example Hydra syntax:

```bash
hydra -l username -P wordlist.txt ssh://TARGET
```

Example SQLMap syntax:

```bash
sqlmap -u 'http://TARGET/item?id=1' --dbs
sqlmap -u 'http://TARGET/item?id=1' -D DATABASE --tables
sqlmap -u 'http://TARGET/item?id=1' -D DATABASE -T TABLE --dump
```

## Digital Forensics and Incident Response

### Digital forensics

A typical forensic workflow is **collection, examination, analysis, and reporting**.

Evidence acquisition should include:

- Proper authorization and a documented scope.
- A complete chain of custody.
- Write blockers for storage media where appropriate.
- Cryptographic hashes to verify evidence integrity.
- Preservation of the original evidence and analysis on a working copy.

For Windows investigations:

- **Disk images:** FTK Imager for acquisition; Autopsy for analysis.
- **Memory images:** DumpIt or an equivalent acquisition tool; Volatility for analysis.
- **Metadata:** `pdfinfo document.pdf` and `exiftool image.jpg`.

### Incident response

Common incident categories include malware infections, security breaches, data leaks, insider threats, and denial-of-service attacks.

A common response lifecycle is:

1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons learned

## Logs and SIEM

### Why logs matter

Logs support security monitoring, incident investigation, forensic analysis, troubleshooting, performance monitoring, auditing, and compliance.

Common log categories include system, security, application, audit, network, and web-access logs.

### Windows Event Viewer

| Event ID | Meaning |
| --- | --- |
| `4625` | An account failed to log on |
| `4634` | An account was logged off |
| `4720` | A user account was created |
| `4722` | A user account was enabled |
| `4724` | An attempt was made to reset an account password |
| `4725` | A user account was disabled |
| `4726` | A user account was deleted |
| `4688` | A new process was created |
| `104` | The event log was cleared |

Event IDs are most useful when correlated with the account, host, timestamp, command line, source address, and surrounding events.

### SIEM fundamentals

SIEM means **Security Information and Event Management**. A SIEM generally provides:

- Centralized log collection.
- Parsing and normalization.
- Cross-source correlation.
- Real-time alerting.
- Dashboards, reporting, and retention.

Log sources are often divided into host-centric sources, such as Windows Event Logs and Linux authentication logs, and network-centric sources, such as firewalls, proxies, IDS sensors, and DNS resolvers.

Common Linux paths vary by distribution and service:

| Source | Common locations |
| --- | --- |
| Apache or HTTP logs | `/var/log/apache2/`, `/var/log/httpd/` |
| Cron | `/var/log/cron`, `/var/log/syslog`, or the system journal |
| Authentication | `/var/log/auth.log`, `/var/log/secure`, or the system journal |
| Kernel | `/var/log/kern.log` or the system journal |

## Firewalls and IDS

### Firewall types

- **Stateless firewall:** Evaluates each packet independently, commonly using Layer 3 and Layer 4 fields.
- **Stateful firewall:** Tracks connection state and makes decisions using both packet attributes and the connection state table.
- **Proxy firewall:** Terminates connections and inspects application-layer requests. It can provide content filtering and application control.
- **Next-generation firewall (NGFW):** Combines stateful filtering with capabilities such as application identification, intrusion prevention, and threat intelligence. TLS inspection is possible only when correctly configured and when the organization can lawfully manage the relevant trust certificates.

Typical rule fields are source address, destination address, source and destination port, protocol, direction, and action. Common actions include allow, deny, reject, and—on some devices—forward or redirect.

Windows Defender Firewall uses network profiles such as Domain, Private, and Public. On Linux, common firewall technologies include Netfilter, `nftables`, `iptables` (legacy on many systems), `firewalld`, and UFW.

Useful UFW commands:

```bash
sudo ufw status numbered
sudo ufw delete RULE_NUMBER
sudo ufw default allow outgoing
sudo ufw deny 22/tcp
```

### Intrusion Detection Systems

An IDS detects suspicious activity; an IPS can additionally block or modify traffic. Deployment models include:

- **HIDS** — Host-based IDS.
- **NIDS** — Network-based IDS.

Detection approaches include signature-based, anomaly-based, and hybrid detection. Snort can operate as a packet sniffer, packet logger, or NIDS.

Typical Snort 3 locations include `/etc/snort/`, `snort.lua`, and a rules directory. A rule has the general form:

```text
alert icmp any any -> 127.0.0.1 any (msg:"Loopback Ping Detected"; sid:1000003; rev:1;)
```

The fields represent the action, protocol, source, direction, destination, and rule metadata. A local rule should use a locally assigned SID range appropriate to the installation.

Example commands:

```bash
sudo snort -q -l /var/log/snort -i lo -A alert_fast -c /etc/snort/snort.lua
sudo snort -q -l /var/log/snort -r Task.pcap -A alert_fast -c /etc/snort/snort.lua
```

## Vulnerability Management

### Scanning perspectives

- **Authenticated scan:** Uses credentials to inspect installed software, patches, configuration, and local weaknesses. It generally provides deeper coverage.
- **Unauthenticated scan:** Assesses what an external or unprivileged observer can see.
- **Internal scan:** Models an attacker or user inside the network.
- **External scan:** Models exposure from the Internet.

Common tools include Nessus, Qualys, Nexpose, and OpenVAS/Greenbone Vulnerability Management.

CVSS severity bands commonly used for CVSS v3.x are:

| Score | Severity |
| --- | --- |
| `0.0` | None |
| `0.1–3.9` | Low |
| `4.0–6.9` | Medium |
| `7.0–8.9` | High |
| `9.0–10.0` | Critical |

Severity is not the same as business risk; asset value, exploitability, exposure, and compensating controls also matter.

## Malware Analysis Tooling

### CAPA and malware behavior frameworks

CAPA performs static analysis to identify capabilities in executable files, such as network communication, file manipulation, process injection, or persistence. It does not replace dynamic analysis.

- **MITRE ATT&CK** — Knowledge base of adversary tactics and techniques.
- **MBC** — Malware Behavior Catalog, which describes malware behaviors in a structured way.
- **MAEC** — Malware Attribute Enumeration and Characterization, a structured language for describing malware attributes and analysis results.

CAPA rule namespaces commonly use a structure such as:

```text
Capability (rule name)::TLN (top-level namespace)/namespace
```

Malware roles may include a launcher, downloader, loader, or other capability-specific behavior.

### Analysis environments

- **REMnux:** Linux toolkit for malware analysis. Common tools include Volatility, YARA, Wireshark, `oledump`, and INetSim.
- **FlareVM:** Windows-based reverse-engineering and malware-analysis environment. Use it in an isolated virtual machine with controlled networking.

## Security Models

- **Bell–LaPadula:** Protects confidentiality. The classic rules are “no read up” and “no write down.”
- **Biba:** Protects integrity. The classic rules are “no read down” and “no write up.”
- **Clark–Wilson:** Protects integrity through well-formed transactions, separation of duties, and controlled transformation procedures.

## Network Scanning with Nmap

### Common options

```bash
nmap -sS TARGET                 # TCP SYN scan; usually requires privileges
nmap -sT TARGET                 # TCP connect scan
nmap -sU TARGET                 # UDP scan
nmap -sV TARGET                 # Service and version detection
nmap -sC TARGET                 # Default NSE scripts
nmap -p- TARGET                 # All TCP ports
nmap -F TARGET                  # Fast scan of a smaller common-port list
nmap -A TARGET                  # OS detection, version detection, scripts, and traceroute
nmap -oN output.txt TARGET     # Normal output
```

`-sS` is sometimes called a half-open scan, but “stealth” or “secret” is not a guarantee: packets and logs can still reveal it. `-sA` is primarily used to map firewall filtering behavior; it does not identify open ports reliably.

Common ports include:

| Port | Typical service |
| --- | --- |
| `20/21` | FTP data/control |
| `22` | SSH and SFTP |
| `23` | Telnet |
| `25` | SMTP |
| `53` | DNS |
| `80` | HTTP |
| `443` | HTTPS |
| `445` | SMB |

### Host discovery and packet options

```bash
nmap -sn TARGET                 # Host discovery; no port scan
nmap -PR TARGET                 # ARP discovery on a local Ethernet segment
nmap -PE TARGET                 # ICMP echo discovery
nmap -PS443 TARGET              # TCP SYN discovery
nmap -PA80 TARGET               # TCP ACK discovery
nmap -PU53 TARGET               # UDP discovery
nmap -R TARGET                  # Always perform reverse DNS
```

Masscan is designed for very high-speed scanning and can generate substantial traffic. Use conservative rates and explicit authorization.

The TCP header is normally 20–60 bytes. Important TCP flags include `URG`, `ACK`, `PSH`, `RST`, `SYN`, and `FIN`.

### TCP and UDP scan behavior

- `-sT` completes the TCP handshake through the operating system.
- `-sS` sends a SYN and interprets SYN/ACK as open and RST as closed without completing the connection.
- `-sU` sends UDP probes. An ICMP port-unreachable response generally indicates closed; no response may indicate open or filtered.

Advanced scans include:

| Scan | Option | General behavior |
| --- | --- | --- |
| Null | `-sN` | No TCP flags set |
| FIN | `-sF` | FIN flag set |
| Xmas | `-sX` | FIN, PSH, and URG flags set |
| Maimon | `-sM` | FIN and ACK flags set |
| ACK | `-sA` | Helps determine filtered versus unfiltered state |
| Window | `-sW` | Uses TCP window differences on some systems |

For Null, FIN, and Xmas scans, responses vary by operating system and firewall. They are not reliable against every modern TCP/IP stack.

Other options include:

```bash
nmap --scan-flags RSTSYNFIN TARGET
nmap -f TARGET                         # Fragment IP packets
nmap -ff TARGET                        # Use more fragmentation
nmap -O TARGET                         # OS detection
nmap --traceroute TARGET
nmap -sI ZOMBIE_IP TARGET              # Idle scan; requires a suitable zombie
nmap --script http-date TARGET
nmap -oX output.xml TARGET
nmap -oG output.gnmap TARGET
nmap -oA scan_results TARGET           # Normal, XML, and grepable output
```

IP spoofing and decoys can interfere with incident response and may be illegal outside a controlled lab. Do not use them without explicit authorization.

The Nmap Scripting Engine uses `.nse` scripts stored on many systems under `/usr/share/nmap/scripts/`. `-sC` runs the default script set; individual scripts can be selected with `--script`.

For local service/version research, Kali's `searchsploit` can search locally installed Exploit-DB data:

```bash
searchsploit openssh
```

## Penetration Testing

### Cyber Kill Chain

The traditional seven-stage Cyber Kill Chain is:

1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command and Control (C2)
7. Actions on Objectives

Reconnaissance may be passive, such as public-source collection and search-engine queries, or active, such as port scanning. Weaponization may involve preparing a malicious document or payload. Delivery can occur through email, a web service, removable media, or another channel. DNS tunneling is generally a C2 or data-exfiltration technique rather than a universal delivery method.

### Testing methodologies

- **OSSTMM** (Open Source Security Testing Methodology Manual) — A methodology organized around measurable operational security; areas include human, physical, wireless, telecommunications, and data-network security. It uses Risk Assessment Values (RAVs) and describes phases such as induction, interaction, inquiry, and intervention.
- **OWASP WSTG** (Web Security Testing Guide) — A guide for testing web applications and web services across the development lifecycle.
- **NIST SP 800-115** — Technical guide for planning and conducting information-security testing, including review techniques, target identification, vulnerability validation, penetration testing, and post-testing activities.
- **PTES** (Penetration Testing Execution Standard) — Covers pre-engagement, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, and reporting.
- **ISSAF** (Information Systems Security Assessment Framework) — Describes planning, information gathering, network mapping, vulnerability identification, penetration, privilege escalation, further enumeration, maintaining access, cleanup, and reporting.
- **MITRE ATT&CK** — A knowledge base of observed adversary behavior used for threat-informed testing and detection mapping.

## Wireless Security

- **SSID** — The service-set identifier displayed as the wireless network name.
- **BSSID** — The MAC address identifying a specific access point radio.
- **ESSID** — Often used interchangeably with SSID in practice; technically it identifies an extended service set.
- **WPA2-Personal / PSK** — Uses a shared pre-shared key.
- **WPA2-Enterprise / EAP** — Uses per-user or per-device authentication, commonly through a RADIUS server.

WPA/WPA2 networks use a four-way handshake. WPA2-PSK keys are commonly tested offline after capturing the relevant handshake or PMKID, subject to authorization. The passphrase is typically 8–63 characters; the underlying PSK is 256 bits.

Aircrack-ng tools include:

- `airmon-ng` — Enable monitor mode on a compatible adapter.
- `airodump-ng` — Discover networks and capture frames.
- `aireplay-ng` — Inject frames, including deauthentication frames, in authorized labs.
- `aircrack-ng` — Test captured handshakes against a wordlist.

```bash
aircrack-ng capture.pcapng -w password_wordlist.txt
```

EAPOL is the protocol used for 802.1X authentication exchanges, including the WPA four-way handshake. WEP is an obsolete and insecure predecessor to WPA.

## Protocols and Network Services

### Web servers and HTTP

Common HTTP servers and application stacks include Apache, Nginx, Microsoft IIS, and Node.js applications. HTTP versions include HTTP/1.1, HTTP/2, and HTTP/3. HTTP/3 uses QUIC over UDP, usually port 443.

### FTP and file transfer

- **FTP** — Usually control on TCP port 21 and a separate data connection. It is cleartext unless protected.
- **SFTP** — File transfer over SSH, usually TCP port 22.
- **FTPS** — FTP protected with TLS; implicit FTPS commonly uses port 990, while explicit TLS can use port 21.
- **SCP** — Secure copy over SSH. It remains widely available, although SFTP is generally preferred for richer file-transfer operations.

Useful FTP commands include `STAT`, `SYST`, `PASV`, and `TYPE A` or `TYPE I` for ASCII or binary transfer. Anonymous FTP, when enabled, commonly uses username `anonymous` or `ftp`; the password may be any value, but this is server-specific.

Common FTP servers include `vsftpd`, ProFTPD, and Pure-FTPd.

### Email protocols

SMTP roles include the Mail User Agent (MUA), Mail Submission Agent (MSA), Mail Transfer Agent (MTA), and Mail Delivery Agent (MDA).

| Service | Port | Notes |
| --- | --- | --- |
| SMTP relay | `25` | Server-to-server; TLS may be negotiated with STARTTLS |
| Message submission | `587` | Client submission; authentication and STARTTLS are common |
| Implicit TLS SMTP | `465` | TLS begins immediately |
| POP3 | `110` | Retrieval; cleartext unless upgraded with STLS |
| POP3 over TLS | `995` | Implicit TLS |
| IMAP | `143` | Mail access; can use STARTTLS |
| IMAP over TLS | `993` | Implicit TLS |

Example SMTP commands in a controlled plain-text test session include `EHLO`, `MAIL FROM:`, `RCPT TO:`, `DATA`, and a single period (`.`) on its own line to end the message. Sender spoofing is mitigated—not eliminated—by mechanisms such as SPF, DKIM, and DMARC.

POP3 commands include `USER`, `PASS`, `STAT`, `LIST`, and `RETR 1`. POP3 commonly downloads messages and may delete them, whereas IMAP keeps messages on the server and synchronizes folders and state. IMAP commands include `LOGIN`, `LIST "" "*"`, and `EXAMINE INBOX`.

### Protocol summary

| Protocol | Default port | Purpose | Secure alternative |
| --- | ---: | --- | --- |
| FTP | 21 | File transfer | FTPS or SFTP |
| HTTP | 80 | Web | HTTPS on 443 |
| Telnet | 23 | Remote access | SSH on 22 |
| SMTP | 25 | Mail transfer | STARTTLS, submission on 587, or implicit TLS on 465 |
| POP3 | 110 | Mail retrieval | POP3S on 995 |
| IMAP | 143 | Mail access | IMAPS on 993 |

## Traffic Analysis and TLS

### Packet capture

Tools include `tcpdump`, Wireshark, TShark, `tcpflow`, `ngrep`, and NetworkMiner. NetworkMiner can extract certain files and images from captures; results must be validated.

```bash
sudo tcpdump -i INTERFACE -nn -A host TARGET_IP and port PORT
sudo tcpdump -i INTERFACE -w capture.pcap
tcpdump -r capture.pcap
```

### Man-in-the-middle attacks

Examples include ARP spoofing, DNS spoofing, rogue access points, and BGP hijacking. Tools used in authorized demonstrations include Bettercap, Ettercap, mitmproxy, and Responder. Defenses include authenticated encryption, certificate validation, HSTS, secure network segmentation, and monitoring for anomalous ARP or DNS behavior.

SSL stripping, forged certificates, and compromised certificate authorities are examples of attacks against encrypted communications. They depend on specific conditions and are not interchangeable techniques.

### TLS

SSL 2.0 and SSL 3.0 are obsolete. TLS 1.0 and 1.1 are deprecated; TLS 1.2 and TLS 1.3 are the commonly supported modern versions. A simplified TLS handshake includes ClientHello, ServerHello, certificate and key-exchange messages, key establishment, and encrypted application data. The exact message flow differs by TLS version and authentication mode.

Useful testing tools include:

- `testssl.sh`
- `sslyze`
- Qualys SSL Labs
- Nmap's `ssl-enum-ciphers` NSE script

DNS over TLS uses TCP port 853. DNS over HTTPS uses HTTPS, normally TCP port 443.

## Web Enumeration and Content Discovery

### Gobuster

```bash
gobuster dir -u http://TARGET/ -w wordlist.txt -t 50 -o results.txt
gobuster dir -u https://TARGET/ -w wordlist.txt -x php,txt,bak -k
gobuster dns -d example.com -w subdomains.txt -i
gobuster vhost -u http://TARGET/ -w vhosts.txt --append-domain
```

Useful options include `-t` for threads, `-o` for output, `-w` for a wordlist, `--delay` for rate limiting, `-x` for file extensions, `-r` to follow redirects, and `-k` to skip TLS certificate validation in a lab. `-s` selects status codes to display; check the installed version with `gobuster help` because option names can change.

A **subdomain** is resolved through DNS. A **virtual host** is selected by the web server using the HTTP `Host` header; multiple virtual hosts can share one IP address.

Local name resolution is commonly configured in `/etc/hosts`. Resolver configuration is commonly found in `/etc/resolv.conf`; `/etc/dnsmasq.conf` is used when dnsmasq is installed and configured.

Nikto performs automated web-server checks:

```bash
nikto -h http://TARGET:PORT
```

## Modern Web Stacks

### MERN

MERN consists of MongoDB, Express.js, React, and Node.js. Common clues include:

- MongoDB often listens on port 27017 by default, but should not be assumed to be exposed.
- Express may listen on ports such as 3000 or 5000. `X-Powered-By: Express` may reveal the framework unless disabled.
- `connect.sid` is a common Express session-cookie name, not a guarantee of the framework.
- React renders text safely by default; HTML injection generally requires an unsafe rendering path.

Framework error responses can provide clues. For example, Express may return `Cannot GET /path`, Django may expose characteristic headers or an `/admin/` route, and Next.js may include `window.__next_f` in rendered pages. These indicators are version- and configuration-dependent.

The `x-middleware-subrequest` header has appeared in version-specific Next.js middleware bypass research. Do not treat a copied header as a general-purpose technique; verify the affected version, advisory, and lab scope first.

### `curl` reference

```bash
curl -c cookies.txt http://TARGET/             # Save cookies
curl -b cookies.txt http://TARGET/             # Send cookies
curl -X POST -H 'Content-Type: application/json' \
  -d '{"name":"Alice","email":"alice@example.com"}' http://TARGET/api
curl -I http://TARGET/                         # Headers only
curl -sS http://TARGET/                        # Silent progress, show errors
curl -o output.txt http://TARGET/file.txt
curl -u 'user:password' http://TARGET/
curl -T upload.txt http://TARGET/upload
```

### LAMP

LAMP refers to Linux, Apache, MySQL/MariaDB, and PHP. On a typical Debian-based Apache installation, web content may be under `/var/www/html` and the service may run as `www-data`; both are configuration-dependent.

## Web Server Enumeration

Start with response headers, default pages, error behavior, supported HTTP methods, directory listing, and content discovery. Version strings are clues, not proof.

### Common server clues

- Python's built-in HTTP server may return plain-text errors and may expose directory listings.
- Apache may identify itself in headers or default error pages. `/server-status` is available only when the status module and access rules permit it.
- Nginx may identify itself in headers or error pages. `/nginx_status` is not a default public endpoint; it must be explicitly configured.
- Node.js/Express may expose routes such as `/api/`, but route names are application-specific.
- IIS may identify itself with `Server: Microsoft-IIS/10.0` or another version string.

For Nginx on Ubuntu, site configuration is commonly under `/etc/nginx/sites-available/` and enabled through `sites-enabled/`. These paths are useful only after authorized shell access; permissions still apply.

### IIS and WebDAV

IIS commonly uses HTTP.sys for kernel-level HTTP handling, WAS and W3SVC for worker-process management, `w3wp.exe` for application-pool workers, and ASP.NET or another handler for application processing.

WebDAV extends HTTP with methods such as `PROPFIND`, `PROPPATCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, and `UNLOCK`. `PUT` and `DELETE` may also be allowed depending on configuration. A safe method check is:

```bash
curl -X OPTIONS http://TARGET/ -sv 2>&1 | grep -E 'Allow:|DAV:'
```

Common IIS weaknesses include enabled directory listing, unauthenticated write or delete methods, exposed `web.config`, verbose errors, exposed `trace.axd`, enabled TRACE, and application pools running with excessive privileges. `SeImpersonatePrivilege` is a Windows token privilege and is not itself an IIS misconfiguration.

IIS-related Nmap scripts include `http-methods`, `http-webdav-scan`, and `http-ntlm-info`.

IIS short filename enumeration concerns the legacy 8.3 naming convention, such as `XXXXXX~1.EXT`. It is configuration- and version-dependent and should be tested only in an authorized environment.

## Web Application Vulnerabilities

### SQL injection

SQL injection occurs when untrusted input changes a database query's structure. Testing should be performed against a lab or approved target.

Useful SQL concepts include:

- `information_schema.tables` — Table metadata.
- `information_schema.columns` — Column metadata.
- `UNION` — Combines compatible result sets.
- `LIMIT` — Restricts returned rows in databases that support it.
- `LIKE 'A%'` — Values beginning with `A`.
- `LIKE 'A_'` — Two-character values beginning with `A`.
- Comments — Syntax varies by database; common forms include `-- `, `#`, and `/* ... */`.

Basic input probes may include a single quote, double quote, semicolon, and a deliberately invalid expression. Boolean tests such as `OR 1=1` must be adapted to the query context and should never be used against an unapproved system.

In-band SQL injection includes error-based and union-based techniques. Database-specific functions and procedures such as `xp_dirtree` and `xp_cmdshell` apply to Microsoft SQL Server and are not portable SQL techniques. Out-of-band methods require a suitable external interaction channel and careful authorization.

### Cross-site request forgery (CSRF)

CSRF tricks a browser into sending an authenticated request to a site where the victim is already logged in. Defenses include anti-CSRF tokens, SameSite cookies, origin checks, and re-authentication for sensitive operations.

### Cross-site scripting (XSS)

XSS executes attacker-controlled script in another user's browser. Types include reflected, stored, and DOM-based XSS. Blind XSS is stored input that executes later in a privileged viewer, such as an administrator.

```html
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
```

These examples are suitable only for a local lab. XSS Hunter Express and other callback services should never be used against real users without explicit written authorization. Polyglot payloads are context-specific and should be studied from an approved lab rather than copied blindly.

### Session management

Important areas include session creation, tracking, timeout, rotation, and termination. Cookie attributes include:

- `Secure` — Send only over HTTPS.
- `HttpOnly` — Prevent client-side JavaScript from reading the cookie.
- `Expires` or `Max-Age` — Control cookie lifetime.
- `SameSite` — Restrict cross-site sending behavior.

Token-based sessions may use cookies or an `Authorization: Bearer TOKEN` header. JWTs are signed tokens, not automatically encrypted tokens; validate signature, issuer, audience, expiry, and algorithm configuration.

### File inclusion and path traversal

Path traversal attempts to access files outside the intended directory. In PHP, local file inclusion may involve functions such as `include`, `require`, `include_once`, `require_once`, or `file_get_contents` when input is used unsafely.

Remote file inclusion depends on configuration such as `allow_url_fopen` and `allow_url_include`, and is disabled by default in many modern configurations. Null-byte termination tricks (`%00`) are obsolete on current PHP versions but may appear in historical labs. Input filtering is not a substitute for canonicalization, allowlists, and filesystem access controls.

### Command injection

Command injection occurs when input reaches a shell or command interpreter without safe separation. In a permitted lab, a visible-output test might use `; whoami`; blind command injection may be inferred through timing or controlled network interaction. Windows and Unix command syntax differ, and payloads should be tailored to the actual interpreter.

Reference material: [PayloadsAllTheThings command-injection payload list](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection).

## API Testing

REST is an architectural style, not a protocol. Common CRUD operations map approximately to:

| Operation | HTTP methods |
| --- | --- |
| Create | `POST` |
| Read | `GET` |
| Replace | `PUT` |
| Partial update | `PATCH` |
| Delete | `DELETE` |

Common status codes:

| Code | Meaning |
| --- | --- |
| `200` | Successful request |
| `201` | Resource created |
| `204` | Successful request with no response body |
| `400` | Bad request |
| `401` | Missing or invalid authentication |
| `403` | Authenticated but not authorized, or access denied |
| `404` | Resource not found |
| `405` | Method not allowed |
| `429` | Too many requests or rate limit exceeded |
| `500` | Internal server error |

**Broken Object-Level Authorization (BOLA)** occurs when a user can access another user's object by changing an identifier, such as requesting `/users/1` while authenticated as user 4. It is a major API risk. **Mass assignment** occurs when clients can set fields that should be server-controlled by submitting extra object properties.

## Vulnerability Databases and Scanners

### Vulnerability identifiers

- **CVE** — Common Vulnerabilities and Exposures identifier.
- **CVSS** — Common Vulnerability Scoring System severity representation.
- **CPE** — Common Platform Enumeration product/platform identifier.
- **CWE** — Common Weakness Enumeration weakness category.
- **CNA** — CVE Numbering Authority.
- **NVD** — National Vulnerability Database; <https://nvd.nist.gov/>.
- **Exploit Database** — Public exploit references; <https://www.exploit-db.com/>.

### Scanner types

- **Network scanner** — Finds exposed ports, services, and network weaknesses.
- **Web application scanner** — Tests web applications and APIs.
- **Host-based scanner** — Inspects local software, patches, and configuration.

Nikto is a web-server scanner:

```bash
nikto -h TARGET
```

OpenVAS, now commonly delivered through Greenbone Vulnerability Management, performs vulnerability assessment across hosts and services. Scanner findings require manual validation to distinguish false positives from exploitable conditions.

### Attack surface mapping

Organize assessment findings by layer:

- **Network layer:** Open ports, exposed services, and protocols.
- **Operating-system layer:** Users, permissions, services, scheduled tasks, and local configuration.
- **Application layer:** URL parameters, form fields, API objects, headers, authentication, and business logic.

Basic service checks may include:

```bash
nc -nv TARGET_IP PORT
smbclient -L //TARGET_IP -N
smbclient //TARGET_IP/SHARE -N
nmap --script smb2-security-mode -p 445 TARGET_IP
ftp TARGET_IP
```

An SMB null session (`-N`) suppresses the password prompt; it does not guarantee that the server permits anonymous access. FTP anonymous access is server-dependent and should be verified only within scope.

## Phishing Basics

### Phishing Types
- **Phishing** Routine
- **Spear Phishing** Targeted attack tailored for a specific person
- **Whaling** A spear phishing whose targets are senior decision-makers and executives.

### Psychology of Phishing
- **Fear**
- **Trust**
- **Scarcity** make something feel rare
- **Authority**
- **Curiosity**
- **Urgency**

### Phishing Techniques

- **URL and Domain Manipulation** 
  - 'URL Masking', https://tryhackme.com redirecting to http://phisher.com
  - 'Homograph Attacks', google.com > go0gle.com
  - 'Typosquatting', tryhackme.com > tryhacme.com
- **Email Spoofing**
  - spoof "From" field to display a trusted sender, SMTP doesn't have built-in authentication.
 - **Credential Harvesting**
 - **Payload Delivery Mechanisms**
 
### Phishing Tools
 - **Gophish**
 - **EvilNginx**
 - **The Social Engineering Toolkit(SET)**
 
### Recommendation Table
| Metric | What it measures | Benchmark | Suggested Recommendation(s) |
| --- | --- | --- | --- |
| Open Rate | % of users who opened the email. | Industry varies; typical phishing open rates ~50–65% | Targeted refresher training |
| Click Rate | % of all users who clicked a link. | 8–14% acceptable; >14% high risk | Focused security awareness training |
|Credential Entry Rate | % of all users who entered credentials after clicking. | <2% low risk; 2–5% moderate risk; >5% high risk | Phishing site identification training, MFA implementation |
| Attachment Detonation Rate | % of users who opened/executed an attachment. | No formal benchmark; >5–7% suggests risk | Educate on safe handling of attachments, detonation |
| Reporting Rate (24h) | % of users who reported the email within 24h. |	>40% strong; 30–40% average; <30% low | Reporting awareness campaign |
