<img src="https://github.com/aw-junaid/aw-junaid/blob/main/Assets/asset3.webp" alt="Security & Hacking Banner" width="1000" height="250">
<div align="left">
<br>

# Awesome Security & Hacking

<h3>A curated arsenal of tools, exploits, forensics, and CTF resources for ethical hackers</h3>

<p>
  <img src="https://img.shields.io/github/stars/aw-junaid/Security-and-Hacking?style=for-the-badge&color=yellow" alt="Stars">
  <img src="https://img.shields.io/github/forks/aw-junaid/Security-and-Hacking?style=for-the-badge&color=blue" alt="Forks">
  <img src="https://img.shields.io/github/issues/aw-junaid/Security-and-Hacking?style=for-the-badge&color=red" alt="Issues">
  <img src="https://img.shields.io/github/last-commit/aw-junaid/Security-and-Hacking?style=for-the-badge&color=purple" alt="Last Commit">
  <img src="https://img.shields.io/badge/License-CC0-brightgreen?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/PRs-welcome-orange?style=for-the-badge" alt="PRs Welcome">
</p>

<p>
  <a href="#network">Network</a> •
  <a href="#endpoint">Endpoint</a> •
  <a href="#web-application-security">Web</a> •
  <a href="#reverse-engineering">Reverse Engineering</a> •
  <a href="#cryptography">Cryptography</a> •
  <a href="#ctf">CTF</a> •
  <a href="#wargames--practice-labs">Wargames</a> •
  <a href="#bug-bounty">Bug Bounty</a>
</p>

</div>

> A curated, professionally organized collection of tools, frameworks, honeypots, forensics utilities, threat intelligence sources, books, wargames, and CTF platforms for ethical hacking, penetration testing, and defensive security research.


---

## Table of Contents

- [Network](#network)
  - [Network Architecture](#network-architecture)
  - [Scanning / Reconnaissance / Pentesting](#scanning--reconnaissance--pentesting)
  - [Monitoring / Logging](#monitoring--logging)
  - [IDS / IPS / Host IDS / Host IPS](#ids--ips--host-ids--host-ips)
  - [Honeypots / Honeynets](#honeypots--honeynets)
  - [Full Packet Capture / Network Forensics](#full-packet-capture--network-forensics)
  - [Sniffers](#sniffers)
  - [SIEM](#siem)
  - [VPN](#vpn)
  - [Fast Packet Processing](#fast-packet-processing)
  - [Firewalls](#firewalls)
  - [Anti-Spam](#anti-spam)
  - [Docker Images for Pentesting & Security](#docker-images-for-pentesting--security)
- [Endpoint](#endpoint)
  - [Anti-Virus / Anti-Malware](#anti-virus--anti-malware)
  - [Content Disarm & Reconstruct](#content-disarm--reconstruct)
  - [Configuration Management](#configuration-management)
  - [Authentication](#authentication)
  - [Mobile / Android / iOS](#mobile--android--ios)
  - [Digital Forensics & Incident Response](#digital-forensics--incident-response)
- [Threat Intelligence](#threat-intelligence)
- [Social Engineering](#social-engineering)
- [Web Application Security](#web-application-security)
  - [Organizations](#organizations)
  - [Web Application Firewalls](#web-application-firewalls)
  - [Scanning / Pentesting](#scanning--pentesting)
  - [Runtime Application Self-Protection](#runtime-application-self-protection)
  - [Secure Development](#secure-development)
- [Reverse Engineering](#reverse-engineering)
  - [Disassemblers & Debuggers](#disassemblers--debuggers)
  - [Decompilers](#decompilers)
  - [Deobfuscators](#deobfuscators)
  - [Binary Examination & Editing](#binary-examination--editing)
  - [Execution Logging & Tracing](#execution-logging--tracing)
- [Cryptography](#cryptography)
- [Exploits & Payloads](#exploits--payloads)
- [Red Team Infrastructure](#red-team-infrastructure)
- [Blue Team Infrastructure](#blue-team-infrastructure)
- [Post-Exploitation](#post-exploitation)
- [DevOps / Supply Chain Security](#devops--supply-chain-security)
- [Big Data & Security Analytics](#big-data--security-analytics)
- [Datastores & Secrets Management](#datastores--secrets-management)
- [Fraud Prevention](#fraud-prevention)
- [Operating Systems](#operating-systems)
- [Wargames & Practice Labs](#wargames--practice-labs)
- [CTF](#ctf)
  - [Competitions](#competitions)
  - [Platforms & Trackers](#platforms--trackers)
- [Bug Bounty](#bug-bounty)
- [Books & EBooks](#books--ebooks)
- [Other Awesome Lists](#other-awesome-lists)

---

## Network

### Network Architecture

- [Network-segmentation-cheat-sheet](https://github.com/sergiomarotco/Network-segmentation-cheat-sheet) — Best practices for corporate network segmentation.

### Scanning / Reconnaissance / Pentesting

- [Nmap](https://nmap.org) — The standard free and open-source utility for network discovery and security auditing.
- [RustScan](https://github.com/RustScan/RustScan) — Rust-based fast port scanner, typically paired with Nmap for deep enumeration.
- [Masscan](https://github.com/robertdavidgraham/masscan) — Internet-scale port scanner.
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) — Framework for developing and executing exploit code against remote targets.
- [OpenVAS](http://www.openvas.org/) — Comprehensive vulnerability scanning and management framework.
- [Kali Linux](https://www.kali.org/) — Debian-derived distribution preloaded with penetration-testing tools.
- [Amass](https://github.com/owasp-amass/amass) — In-depth DNS/subdomain enumeration via scraping, brute forcing, and web-archive crawling.
- [Sublist3r](https://github.com/aboul3la/Sublist3r) — Fast subdomain enumeration tool.
- [Subfinder](https://github.com/projectdiscovery/subfinder) — Passive subdomain discovery tool built for speed and reconnaissance pipelines.
- [naabu](https://github.com/projectdiscovery/naabu) — Fast port scanner designed to chain into further recon tooling.
- [httpx](https://github.com/projectdiscovery/httpx) — Fast, multi-purpose HTTP toolkit for probing large target lists.
- [nuclei](https://github.com/projectdiscovery/nuclei) — Template-driven vulnerability scanner covering thousands of known CVEs and misconfigurations.
- [ffuf](https://github.com/ffuf/ffuf) — Fast web fuzzer for directories, parameters, and virtual hosts.
- [Recon-ng](https://github.com/lanmaster53/recon-ng) — Full-featured web reconnaissance framework with a Metasploit-like interface.
- [Legion](https://github.com/GoVanguard/legion) — Semi-automated network reconnaissance and vulnerability scanning framework.
- [Boofuzz](https://github.com/jtpereyda/boofuzz) — Fuzzing engine and framework.
- [Pompem](https://github.com/rfunix/Pompem) — Automates exploit search across major exploit databases.
- [scapy](https://github.com/secdev/scapy) — Python-based interactive packet manipulation library.
- [pig](https://github.com/rafael-santiago/pig) — Linux packet crafting tool.
- [tsurugi](https://tsurugi-linux.org/) — Linux distribution for DFIR, malware analysis, and OSINT.
- [Deepfence ThreatMapper](https://github.com/deepfence/ThreatMapper) — Runtime vulnerability scanner for Kubernetes, VMs, and serverless.
- [Deepfence SecretScanner](https://github.com/deepfence/SecretScanner) — Finds secrets and credentials in container images and file systems.
- [Cognito Scanner](https://github.com/padok-team/cognito-scanner) — CLI tool for pentesting AWS Cognito instances.

### Monitoring / Logging

- [wazuh](https://github.com/wazuh/wazuh) — Free, open-source XDR/SIEM platform for threat prevention, detection, and response.
- [Falco](https://falco.org/) — CNCF runtime security project; the de facto Kubernetes threat detection engine.
- [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/) — Network traffic probe showing usage similar to the Unix `top` command.
- [Fibratus](https://github.com/rabbitstack/fibratus) — Exploration and tracing of the Windows kernel.
- [OpenSnitch](https://github.com/evilsocket/opensnitch) — GNU/Linux port of the Little Snitch application firewall.
- [passivedns](https://github.com/gamelinux/passivedns) — Passively collects DNS records to aid incident handling and NSM.
- [ngrep](http://ngrep.sourceforge.net/) — grep-like tool applied to network payloads.
- [sagan](http://sagan.quadrantsec.com/) — Snort-like log analysis engine (syslog, event log, SNMP trap, NetFlow).
- [Matano](https://github.com/matanolabs/matano) — Serverless security lake on AWS with Apache Iceberg and real-time Python detections.
- [VAST](https://github.com/tenzir/vast) — Security data pipeline engine for structured event data at scale.
- [Substation](https://github.com/brexhq/substation) — Cloud-native data pipeline and transformation toolkit written in Go.

### IDS / IPS / Host IDS / Host IPS

- [Snort](https://www.snort.org/) — Widely used open-source network intrusion detection/prevention system.
- [Suricata](https://suricata.io/) — High-performance IDS/IPS and network security monitoring engine.
- [Zeek](https://zeek.org/) — Powerful network analysis framework distinct from typical signature-based IDS.
  - [zeek2es](https://github.com/corelight/zeek2es) — Converts Zeek TSV logs to Elastic/OpenSearch or pure JSON.
- [Security Onion](https://securityonionsolutions.com/) — Linux distro bundling Snort, Suricata, Zeek, and other NSM tooling.
- [OSSEC](https://www.ossec.net/) — Open-source host IDS: log analysis, file integrity monitoring, rootkit detection, active response.
- [Wazuh](https://github.com/wazuh/wazuh) — See above; also functions as a host IDS.
- [CrowdSec](https://github.com/crowdsecurity/crowdsec) — Collaborative behavior detection engine with a shared IP reputation network.
- [Fail2Ban](http://www.fail2ban.org/wiki/index.php/Main_Page) — Bans IPs showing malicious log behavior.
- [Lynis](https://cisofy.com/lynis/) — Security auditing tool for Linux/Unix.
- [AIEngine](https://github.com/camp0/aiengine) — Programmable packet inspection engine with NIDS functionality and DNS classification.
- [SSHGuard](https://www.sshguard.net/) — Protects SSH and other services from brute-force attacks.

### Honeypots / Honeynets

- [awesome-honeypots](https://github.com/paralax/awesome-honeypots) — The canonical honeypot resource list.
- [Conpot](https://github.com/mushorg/conpot) — Low-interaction ICS/SCADA honeypot.
- [Cowrie](https://github.com/cowrie/cowrie) — Medium-to-high interaction SSH/Telnet honeypot; the modern successor to Kippo, logging full shell interaction.
- [T-Pot](https://github.com/telekom-security/tpotce) — Dockerized multi-honeypot platform bundling many honeypot daemons behind a single interface.
- [HonSSH](https://github.com/tnich/honssh) — High-interaction honeypot that proxies attacker sessions to a real honeypot.
- [Glastopf](https://github.com/mushorg/glastopf) — Web application honeypot emulating thousands of vulnerabilities.
- [Cuckoo Sandbox](https://cuckoosandbox.org/) — Automated dynamic malware analysis sandbox.

### Full Packet Capture / Network Forensics

- [tcpflow](https://github.com/simsong/tcpflow) — Captures and reconstructs TCP flow data for protocol analysis.
- [Moloch/Arkime](https://github.com/arkime/arkime) — Large-scale PCAP indexing, search, and export platform (Moloch was renamed Arkime).
- [Xplico](https://github.com/xplico/xplico) — Network Forensic Analysis Tool extracting application data from captured traffic.
- [Deepfence PacketStreamer](https://github.com/deepfence/PacketStreamer) — Distributed remote packet capture for cloud-native environments.
- [Dshell](https://github.com/USArmyResearchLab/Dshell) — Network forensic analysis framework for rapid plugin development.
- [Stenographer](https://github.com/google/stenographer) — Fast full-packet spool-to-disk capture with quick subset retrieval.

### Sniffers

- [Wireshark](https://www.wireshark.org) — The standard free, open-source packet analyzer.
- [netsniff-ng](http://netsniff-ng.org/) — High-performance Linux networking toolkit using zero-copy mechanisms.
- [tcpdump](https://www.tcpdump.org/) — Command-line packet analyzer built on libpcap.

### SIEM

- [Wazuh](https://github.com/wazuh/wazuh) — Free, enterprise-ready SIEM/XDR with an OpenSearch-based backend.
- [OSSIM](https://www.alienvault.com/open-threat-exchange/projects) — Open-source SIEM with event collection, normalization, and correlation.
- [FIR](https://github.com/certsocietegenerale/FIR) — Fast Incident Response, a cybersecurity incident management platform.
- [Prelude SIEM](https://www.prelude-siem.org/) — Vendor-agnostic universal SIEM.
- [TheHive](https://github.com/TheHive-Project/TheHive) — Scalable, open-source Security Incident Response Platform, commonly paired with MISP and Cortex for triage and case management.

### VPN

- [OpenVPN](https://openvpn.net/) — Open-source VPN implementation using SSL/TLS for key exchange.
- [WireGuard](https://www.wireguard.com/) — Modern, minimal, high-performance VPN protocol built into the Linux kernel.
- [Firezone](https://github.com/firezone/firezone) — Open-source VPN server and egress firewall for Linux built on WireGuard.

### Fast Packet Processing

- [DPDK](https://www.dpdk.org/) — Libraries and drivers for fast userspace packet processing.
- [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) — High-speed packet capture socket type for Linux.
- [netmap](http://info.iet.unipi.it/~luigi/netmap/) — Framework for high-speed packet I/O across FreeBSD, Linux, and Windows.

### Firewalls

- [pfSense](https://www.pfsense.org/) — FreeBSD-based firewall/router distribution.
- [OPNsense](https://opnsense.org/) — Open-source, easy-to-build FreeBSD-based firewall and routing platform.
- [fwknop](https://www.cipherdyne.org/fwknop/) — Protects ports via Single Packet Authorization.

### Anti-Spam

- [rspamd](https://github.com/rspamd/rspamd) — Fast, free, open-source spam filtering system.
- [SpamAssassin](https://spamassassin.apache.org/) — Widely deployed email spam filter.

### Docker Images for Pentesting & Security

- `docker pull kalilinux/kali-rolling` — [Official Kali Linux](https://hub.docker.com/r/kalilinux/kali-rolling/)
- `docker pull zaproxy/zap-stable` — [Official OWASP ZAP](https://github.com/zaproxy/zaproxy)
- `docker pull wpscanteam/wpscan` — [Official WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
- `docker pull metasploitframework/metasploit-framework` — [Official Metasploit](https://hub.docker.com/r/metasploitframework/metasploit-framework/)
- `docker pull vulnerables/web-dvwa` — [Damn Vulnerable Web Application (DVWA)](https://hub.docker.com/r/vulnerables/web-dvwa/)
- `docker pull bkimminich/juice-shop` — [OWASP Juice Shop](https://hub.docker.com/r/bkimminich/juice-shop)
- `docker pull citizenstig/nowasp` — [OWASP Mutillidae II](https://hub.docker.com/r/citizenstig/nowasp/)
- `docker pull jeroenwillemsen/wrongsecrets` — [OWASP WrongSecrets](https://hub.docker.com/r/jeroenwillemsen/wrongsecrets)
- `docker-compose up` — [cicd-goat](https://github.com/cider-security-research/cicd-goat) — Vulnerable CI/CD pipeline environment for practicing supply-chain attacks defensively.

## Endpoint

### Anti-Virus / Anti-Malware

- [ClamAV](https://www.clamav.net/) — Open-source antivirus engine.
- [LOKI](https://github.com/Neo23x0/Loki) — Simple IOC and incident response scanner.
- [rkhunter](http://rkhunter.sourceforge.net/) — Rootkit hunter for Linux.
- [Linux Malware Detect](https://www.rfxn.com/projects/linux-malware-detect/) — Malware scanner built around shared-hosting threats.
- [YARA](https://github.com/VirusTotal/yara) — Pattern-matching engine widely used for malware classification and hunting.

### Content Disarm & Reconstruct

- [DocBleach](https://github.com/docbleach/DocBleach) — Open-source CDR software sanitizing Office, PDF, and RTF documents.

### Configuration Management

- [Fleet](https://github.com/fleetdm/fleet) — Lightweight, programmable device telemetry platform.
- [Rudder](https://www.rudder.io/) — Role-based IT infrastructure automation and compliance platform.

### Authentication

- [Google Authenticator](https://github.com/google/google-authenticator) — HOTP/TOTP one-time passcode generators and PAM module.
- [Keycloak](https://www.keycloak.org/) — Open-source identity and access management with SSO, OAuth2/OIDC, and SAML support.

### Mobile / Android / iOS

- [OWASP Mobile Security Testing Guide](https://github.com/OWASP/owasp-mstg) — Comprehensive manual for mobile app security testing and reverse engineering.
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — Automated static/dynamic mobile application security testing framework.
- [Apktool](https://github.com/iBotPeaches/Apktool) — Reverse engineering tool for Android APK files.
- [jadx](https://github.com/skylot/jadx) — Dex-to-Java-source decompiler with CLI and GUI.
- [Frida](https://github.com/frida/frida) — Dynamic instrumentation toolkit for developers and researchers.
- [Quark-Engine](https://github.com/quark-engine/quark-engine) — Obfuscation-neglect Android malware scoring system.
- [reFlutter](https://github.com/ptswarm/reFlutter) — Flutter application reverse engineering framework.
- [android-security-awesome](https://github.com/ashishb/android-security-awesome) — Curated collection of Android security resources.

### Digital Forensics & Incident Response

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) — Python-based memory extraction and analysis framework.
- [GRR Rapid Response](https://github.com/google/grr) — Incident response framework for remote live forensics at scale.
- [Velociraptor](https://github.com/Velocidex/velociraptor) — Endpoint monitoring, forensics, and response tool with its own query language (VQL).
- [KAPE (Kroll Artifact Parser and Extractor)](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) — Fast triage tool for targeted collection and processing of forensic artifacts.
- [Timesketch](https://github.com/google/timesketch) — Collaborative timeline analysis for forensic investigations.
- [Rekall](https://github.com/google/rekall) — Framework for extraction and analysis of digital artifacts from memory.
- [LiME](https://github.com/504ensicsLabs/LiME) — Linux Memory Extractor, a loadable kernel module for RAM acquisition.
- [Maigret](https://github.com/soxoj/maigret) — Collects a dossier on a person by username across a large number of sites.

## Threat Intelligence

- [MISP](https://www.misp-project.org/) — Open-source threat intelligence and sharing platform, with taxonomies, galaxies, and default feeds.
- [MITRE ATT&CK](https://attack.mitre.org/) — Globally accessible knowledge base of adversary tactics and techniques based on real-world observation.
- [abuse.ch](https://abuse.ch/) — Trackers and blocklists (URLhaus, ThreatFox, MalwareBazaar) for malware and C2 infrastructure.
- [VirusTotal](https://www.virustotal.com/) — Aggregates dozens of antivirus engines and scanners to analyze files and URLs.
- [AlienVault OTX](https://otx.alienvault.com/) — Open Threat Exchange for community-shared indicators of compromise.
- [PhishTank](https://phishtank.org/) — Collaborative clearing house for phishing data with a free API.
- [Spamhaus](https://www.spamhaus.org/) — Realtime anti-spam blocklists (SBL/XBL/PBL/DBL/DROP).
- [IntelMQ](https://github.com/certtools/intelmq) — Message-queue-based solution for CERTs to collect and process threat feeds.
- [CIFv2 / CIF-Router](https://github.com/csirtgadgets) — Cyber threat intelligence combination and mitigation framework.
- [FireEye/Mandiant OpenIOCs](https://github.com/mandiant/OpenIOC_1.1) — Publicly shared indicators of compromise.

## Social Engineering

- [Gophish](https://getgophish.com/) — Open-source phishing simulation framework.
- [Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit) — Framework for simulating social-engineering attack vectors in authorized assessments.

## Web Application Security

### Organizations

- [OWASP](https://owasp.org) — Nonprofit foundation focused on improving software security, publisher of the Top 10 and ASVS.
- [PortSwigger](https://portswigger.net) — Makers of Burp Suite and the Web Security Academy (free training).

### Web Application Firewalls

- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) — Toolkit for real-time web application monitoring, logging, and access control.
- [NAXSI](https://github.com/nbs-system/naxsi) — High-performance, low-maintenance WAF module for NGINX.
- [BunkerWeb](https://github.com/bunkerity/bunkerweb) — Full-featured open-source web server with an integrated WAF, automatic HTTPS, and bot/bad-IP blocking.
- [Curiefense](https://github.com/curiefense/curiefense) — Adds automated web security tooling, including a WAF, to Envoy Proxy.
- [open-appsec](https://github.com/openappsec/openappsec) — Machine-learning security engine that preemptively blocks threats against web apps and APIs.

### Scanning / Pentesting

- [Burp Suite Community/Pro](https://portswigger.net/burp) — The de facto standard interception proxy and web vulnerability scanner.
- [sqlmap](https://sqlmap.org/) — Automates detection and exploitation of SQL injection flaws.
- [OWASP ZAP](https://www.zaproxy.org/) — Integrated web application penetration-testing proxy and scanner.
- [w3af](https://github.com/andresriancho/w3af) — Web Application Attack and Audit Framework.
- [katana](https://github.com/projectdiscovery/katana) — Next-generation crawling and spidering framework.
- [gau (GetAllUrls)](https://github.com/lc/gau) — Fetches known URLs from AlienVault OTX, Wayback Machine, and Common Crawl.
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Extensive list of payloads and bypasses for web app security and CTFs.
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — Structured methodology for testing web application security.

### Runtime Application Self-Protection

- [OpenRASP](https://github.com/baidu/openrasp) — Open-source RASP solution with a context-aware detection algorithm and low overhead.

### Secure Development

- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) — Checklist-driven standard for testing web applications by assurance level.
- [Checkov](https://github.com/bridgecrewio/checkov) — Static analysis for infrastructure-as-code (Terraform, CloudFormation, Kubernetes).
- [KICS](https://github.com/Checkmarx/kics) — Scans IaC projects (Terraform, Kubernetes, Docker, Ansible) for vulnerabilities and misconfigurations.
- [Semgrep](https://github.com/semgrep/semgrep) — Fast, lightweight static analysis tool supporting custom rules across dozens of languages.
- [Bearer](https://github.com/Bearer/bearer) — Scans code for security risks and sensitive-data exposure.

## Reverse Engineering

### Disassemblers & Debuggers

- [Ghidra](https://ghidra-sre.org/) — NSA-developed software reverse engineering suite.
- [IDA Pro / IDA Free](https://hex-rays.com/ida-free/) — Industry-standard multi-processor disassembler and debugger.
- [radare2](https://github.com/radareorg/radare2) — Portable reverse engineering framework.
- [Cutter](https://github.com/rizinorg/cutter) — Modern GUI built on the Rizin (radare2-derived) framework.
- [x64dbg](https://github.com/x64dbg/x64dbg) — Open-source x64/x32 debugger for Windows.
- [Binary Ninja](https://binary.ninja/) — Commercial reverse engineering platform with a strong scripting API.

### Decompilers

- **JVM-based languages**: [JD-GUI](https://github.com/java-decompiler/jd-gui), [Krakatau](https://github.com/Storyyeller/Krakatau), [JADX](https://github.com/skylot/jadx) (Android)
- **.NET**: [dnSpy](https://github.com/dnSpyEx/dnSpy), [ILSpy](https://github.com/icsharpcode/ILSpy), [dotPeek](https://www.jetbrains.com/decompiler/)
- **Native code**: [RetDec](https://github.com/avast/retdec), [Hex-Rays Decompiler](https://hex-rays.com/decompiler/), [Snowman](https://github.com/yegord/snowman)
- **Python**: [decompyle3](https://github.com/rocky/python-decompile3), [uncompyle6](https://github.com/rocky/python-uncompyle6)

### Deobfuscators

- [de4dot](https://github.com/de4dot/de4dot) — .NET deobfuscator and unpacker.
- [JS Beautifier](https://github.com/beautify-web/js-beautify) — Reformats minified/obfuscated JavaScript for readability.

### Binary Examination & Editing

- [Binwalk](https://github.com/ReFirmLabs/binwalk) — Detects signatures, unpacks archives, and visualizes entropy in binaries.
- [Kaitai Struct](https://github.com/kaitai-io/kaitai_struct) — DSL for building binary format parsers, with a browser-based Web IDE.
- [ImHex](https://github.com/WerWolv/ImHex) — Modern hex editor built for reverse engineers, with pattern language support.
- [DarunGrim](https://github.com/ohjeongwook/DarunGrim) — Binary diffing tool for patch analysis.

### Execution Logging & Tracing

- [mitmproxy](https://github.com/mitmproxy/mitmproxy) — Interactive, SSL-capable man-in-the-middle proxy with a console/scriptable interface.
- [Frida](https://github.com/frida/frida) — Dynamic instrumentation across desktop, mobile, and embedded targets.
- [drltrace](https://github.com/mxmssh/drltrace) — Shared library call tracing.

## Cryptography

- [John the Ripper](https://www.openwall.com/john/) — Fast, widely used password cracker.
- [Hashcat](https://hashcat.net/hashcat/) — GPU-accelerated password recovery tool, the modern standard for offline cracking.
- [Aircrack-ng](https://www.aircrack-ng.org/) — Suite for auditing 802.11 WEP and WPA-PSK security.
- [Ciphey](https://github.com/Ciphey/Ciphey) — Automated decryption using AI/NLP heuristics.
- [CyberChef](https://github.com/gchq/CyberChef) — GCHQ's browser-based "Swiss Army knife" for encoding, decoding, and cryptanalysis.

## Exploits & Payloads

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Extensive payload and bypass reference for web security and CTFs.
- [Exploit Database](https://www.exploit-db.com/) — Archive of exploits and vulnerable software maintained by Offensive Security.
- [GTFOBins](https://gtfobins.github.io/) — Curated list of Unix binaries usable to bypass local security restrictions (privilege escalation reference).
- [LOLBAS](https://lolbas-project.github.io/) — Living-off-the-land binaries, scripts, and libraries reference for Windows.

## Red Team Infrastructure

- [Axiom](https://github.com/pry0cc/axiom) — Dynamic multi-cloud infrastructure framework for offensive and defensive security work.
- [Redcloud](https://github.com/khast3x/Redcloud) — Automated Red Team infrastructure deployment via Docker.
- [Sliver](https://github.com/BishopFox/sliver) — Open-source cross-platform adversary emulation/red-team C2 framework.

## Blue Team Infrastructure

- [MutableSecurity](https://github.com/MutableSecurity/mutablesecurity) — CLI for automating setup, configuration, and use of cybersecurity solutions.
- [HELK](https://github.com/Cyb3rWard0g/HELK) — Hunting ELK stack purpose-built for threat hunting research.

## Post-Exploitation

- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) — PowerShell post-exploitation framework.
- [Empire](https://github.com/BC-SECURITY/Empire) — Post-exploitation framework spanning PowerShell and Python agents (actively maintained fork of the original EmpireProject).
- [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY) — Post-exploitation agent leveraging IronPython to bypass PowerShell restrictions.
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) — Utility for exploring Windows credential and authentication internals.

## DevOps / Supply Chain Security

- [Trivy](https://github.com/aquasecurity/trivy) — Comprehensive vulnerability and misconfiguration scanner for containers and IaC.
- [Cosign / Sigstore](https://github.com/sigstore/cosign) — Container signing, verification, and storage for supply-chain integrity.
- [Teller](https://github.com/tellerops/teller) — Secrets management across multiple vaults and keystores from a single interface.
- [ansible-os-hardening](https://github.com/dev-sec/ansible-os-hardening) — Ansible role for OS hardening baselines.

## Big Data & Security Analytics

- [Apache Metron](https://github.com/apache/metron) — Big-data-driven centralized security monitoring and analysis platform.
- [Matano](https://github.com/matanolabs/matano) — Serverless security lake on AWS built on Apache Iceberg.
- [VAST](https://github.com/tenzir/vast) — Security data pipeline engine for structured event telemetry.

## Datastores & Secrets Management

- [HashiCorp Vault](https://www.vaultproject.io/) — Encrypted datastore for environment and application secrets.
- [SOPS](https://github.com/getsops/sops) — Editor for encrypted files supporting YAML/JSON/BINARY with AWS KMS, GCP KMS, and PGP.
- [acra](https://github.com/cossacklabs/acra) — Database security suite with transparent encryption, masking, and SQL-injection prevention.
- [Passbolt](https://www.passbolt.com/) — Open-source, OpenPGP-based team password manager.

## Fraud Prevention

- [FingerprintJS](https://github.com/fingerprintjs/fingerprintjs) — Browser fingerprinting to detect account takeover and abuse patterns.

## Operating Systems

- [Qubes OS](https://www.qubes-os.org/) — Security-oriented OS built on isolation via virtualization.
- [Whonix](https://www.whonix.org) — OS designed for anonymity, routing all traffic through Tor.
- [Tails](https://tails.net/) — Portable, amnesic OS protecting against surveillance and censorship.
- [Security-related OS list @ Rawsec](https://inventory.raw.pm/operating_systems.html) — Comprehensive index of security-focused operating systems.

## Wargames & Practice Labs

- [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) — The classic entry-level Linux command-line wargame.
- [OverTheWire: Natas](https://overthewire.org/wargames/natas/) — Web-focused wargame teaching common web vulnerability classes.
- [OverTheWire: Krypton](https://overthewire.org/wargames/krypton/) — Introductory cryptography wargame.
- [pwnable.kr](http://pwnable.kr/) — Binary exploitation ("pwn") challenges of increasing difficulty.
- [pwn.college](https://pwn.college/) — Free, structured binary exploitation curriculum from Arizona State University.
- [Exploit Exercises](https://exploit-exercises.lains.space/) — VM-based exercises covering memory corruption and privilege escalation.
- [Crackmes.one](https://crackmes.one/) — Community archive of reverse-engineering crackmes (successor to crackmes.de).
- [Root-Me](https://www.root-me.org/) — Large multi-category hacking challenge platform (web, crypto, forensics, reversing, and more).
- [VulnHub](https://www.vulnhub.com/) — Downloadable vulnerable VMs for offline penetration-testing practice.
- [Hack The Box](https://www.hackthebox.com/) — Subscription and free-tier platform with vulnerable machines and guided tracks.
- [TryHackMe](https://tryhackme.com/) — Hands-on, guided cybersecurity training through browser-based labs.
- [PicoCTF](https://picoctf.org/) — Beginner-friendly, perpetually available CTF built by Carnegie Mellon University.
- [Google Gruyere](https://google-gruyere.appspot.com/) — Small, deliberately vulnerable web app for learning common flaws.

## CTF

### Competitions

- [DEF CON CTF](https://defcon.org/) — The longest-running and most prestigious annual CTF finals.
- [CSAW CTF](https://ctf.csaw.io/) — NYU-Poly's annual student-focused CTF.
- [Insomni'hack](https://insomnihack.ch/) — Swiss CTF and conference.
- [ångstromCTF](https://angstromctf.com/) — High-school-oriented beginner CTF.
- [Google CTF](https://capturetheflag.withgoogle.com/) — Annual CTF run by Google's security team, with a beginner quest track.

### Platforms & Trackers

- [CTFtime.org](https://ctftime.org/) — Global calendar and rating tracker for CTF competitions.
- [CTFd](https://github.com/CTFd/CTFd) — Open-source platform for hosting your own CTF.
- [Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/) — Open-source inventory of tools, CTF platforms, and security operating systems.

## Bug Bounty

- [Bugcrowd](https://www.bugcrowd.com/) — Crowdsourced bug bounty and vulnerability disclosure platform.
- [HackerOne](https://www.hackerone.com/) — Widely used bug bounty and coordinated disclosure platform.
- [Intigriti](https://www.intigriti.com/) — European ethical hacking and bug bounty platform.
- [Awesome Bug Bounty Cheat Sheets](https://github.com/EdOverflow/bugbounty-cheatsheet) — Curated cheat sheets for bug bounty methodology.

## Books & EBooks

- 2023, TCM Security / various — [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Free, continuously updated web security curriculum with hands-on labs (not a book, but the closest thing to a living textbook on web app security).
- Sparc Flow — *How to Hack Like a Pornstar*, *How to Hack Like a Legend*, *How to Investigate Like a Rockstar* — Narrative-driven walkthroughs of realistic offensive engagements.
- Fotios Chantzis et al. — [Practical IoT Hacking](https://nostarch.com/practical-iot-hacking) (No Starch Press, 2021)
- Georgia Weidman — [Penetration Testing: A Hands-On Introduction to Hacking](https://nostarch.com/pentesting) (No Starch Press)
- Peter Kim — [The Hacker Playbook 3: Practical Guide To Penetration Testing](https://www.amazon.com/dp/1980901759)
- Jon Erickson — [Hacking: The Art of Exploitation, 2nd Edition](https://nostarch.com/hacking2) (No Starch Press)
- Chris Anley et al. — [The Shellcoder's Handbook](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)
- [The Security Engineer Handbook](https://securityhandbook.io/) — Short, practical read on working in and around a security team.
- [Holistic Info-Sec for Web Developers](https://holisticinfosecforwebdevelopers.com/) — Free, broad-coverage series on secure software delivery.

## Other Awesome Lists

- [Awesome Hacking](https://github.com/carpedm20/awesome-hacking)
- [Awesome Pentest](https://github.com/enaqx/awesome-pentest)
- [Awesome CTF](https://github.com/apsdehal/awesome-ctf)
- [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
- [Awesome Web Hacking](https://github.com/infoslack/awesome-web-hacking)
- [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response)
- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)
- [Awesome YARA](https://github.com/InQuest/awesome-yara)
- [Awesome Industrial Control System Security](https://github.com/mpesen/awesome-industrial-control-system-security)
- [Awesome Bug Bounty](https://github.com/djadmin/awesome-bug-bounty)
- [Awesome Red Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming)
- [Awesome Threat Detection and Hunting](https://github.com/0x4D31/awesome-threat-detection)

---

## Contributing

Suggestions are welcome — open an issue or pull request with a short description of the resource and why it belongs here. Dead links and abandoned tools are removed as they're found.

## License

[![CC0](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, this work is released under CC0 — free to use, share, and adapt.
