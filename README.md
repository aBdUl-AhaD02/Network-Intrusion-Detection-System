# 🛡️ Network Intrusion Detection System

## 📋 Project Overview

A comprehensive network security monitoring solution implementing Snort IDS on Linux to detect and analyze malicious network traffic. This project demonstrates real-world intrusion detection capabilities through the deployment of thousands of detection rules, custom signature creation, and detailed PCAP analysis.

---

## 🎯 Objective

To build and configure a production-ready Intrusion Detection System capable of identifying various network-based attacks including exploitation attempts, shellcode injection, ARP spoofing, DNS spoofing, and HTTP-based threats. The project focuses on developing practical skills in threat detection, traffic analysis, and security rule optimization.

---

## 🧠 Skills Learned

- **Network Traffic Analysis:** Deep packet inspection and protocol analysis to identify suspicious patterns
- **Intrusion Detection:** Configuring and tuning IDS rules for accurate threat detection
- **Custom Signature Development:** Creating detection rules for specific attack vectors and threat patterns
- **PCAP Analysis:** Examining packet capture files to extract indicators of compromise (IOCs)
- **Threat Identification:** Recognizing various attack types including ARP/DNS spoofing and shellcode injection
- **Rule Optimization:** Fine-tuning detection rules to reduce false positives and improve accuracy
- **Incident Response:** Documenting security events and extracting actionable intelligence from alerts
- **Linux System Administration:** Managing and configuring security tools in Linux environment

---

## 🛠️ Tools Used

- **Snort 3.10.0.0** - Open-source Intrusion Detection System
- **Linux (Ubuntu)** - Operating system platform
- **Wireshark** - Network protocol analyzer for PCAP analysis
- **tcpdump** - Command-line packet analyzer
- **Text Editor (Vim/Nano)** - For creating custom Snort rules
- **Bash Scripting** - Automation of IDS operations

---

## 📝 Steps

### 1. Environment Setup
- Installed Ubuntu Linux in a virtual environment
- Updated system packages and dependencies
- Downloaded and installed Snort 3.10.0.0 from official repository

### 2. Snort Installation & Configuration
```bash
# Install Snort dependencies
sudo apt-get install -y build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev

# Download and compile Snort 3.10.0.0
wget https://www.snort.org/downloads/snort/snort3-3.10.0.0.tar.gz
tar -xvzf snort3-3.10.0.0.tar.gz
cd snort3-3.10.0.0
./configure && make && sudo make install
```

### 3. Rule Configuration
- Downloaded community ruleset containing 4,875 detection rules
- Configured snort.lua file with appropriate network variables
- Organized rules into categories (exploit, malware, web-attacks, etc.)
- Validated rule syntax and tested rule loading

### 4. Custom Signature Development
- Created custom rules to detect specific attack patterns:
  - ARP spoofing detection rules
  - DNS spoofing signatures
  - Shellcode injection patterns
  - HTTP-based attack signatures
- Tested custom rules against known attack traffic
- Documentation of rule logic and detection methodology

### 5. Network Monitoring Setup
- Configured network interface in promiscuous mode
- Set up logging and alert mechanisms
- Defined output formats (fast, full, unified2)
- Configured alert thresholds and suppression rules

### 6. PCAP Analysis
- Collected network traffic samples 
- Analyzed PCAP files containing various attack scenarios
- Ran Snort against captured traffic: `snort -c snort.lua -r capture.pcap`
- Identified and documented indicators of compromise (IOCs)

### 7. Threat Detection & Analysis
- **Detected Threats:**
  - 161 ARP spoofing attempts
  - Multiple DNS spoofing events
  - Shellcode injection patterns
  - HTTP-based exploitation attempts
  - Malicious payload delivery attempts
- Extracted attacker IP addresses, timestamps, and attack signatures
- Correlated multiple alerts to identify attack campaigns

### 8. Performance Optimization
- Analyzed rule performance metrics
- Disabled unnecessary rules to reduce processing overhead
- Implemented rule suppression for known false positives
- Optimized packet processing for better detection accuracy
- Tuned memory and CPU usage for efficient operation

### 9. Documentation & Reporting
- Created detailed incident reports for detected threats
- Documented custom rule logic and effectiveness
- Analyzed false positive rates and improvement strategies
- Generated statistics on threat detection rates

---

## 📊 Key Results

- ✅ Successfully deployed Snort IDS with **4,875 active detection rules**
- ✅ Achieved **100% rule validation** with zero syntax errors
- ✅ Detected **161 ARP spoofing attempts** in network traffic
- ✅ Identified multiple attack categories: exploitation, shellcode, spoofing, HTTP attacks
- ✅ Created **15+ custom signatures** for specific threat patterns
- ✅ Reduced alert response time through rule optimization
- ✅ Extracted **250+ indicators of compromise** from PCAP analysis

---

## 🔍 Sample Custom Rule
```lua
# Detect ARP Spoofing Attempt
alert ( 
    msg:"ARP Spoofing Detected"; 
    flow:to_server; 
    content:"|08 06|"; 
    offset:12; 
    depth:2; 
    classtype:bad-unknown; 
    sid:1000001; 
    rev:1; 
)
```

---

## 📚 What I Learned

This project provided hands-on experience in network security monitoring and intrusion detection. I learned how attackers exploit network protocols, how to identify malicious patterns in network traffic, and how to build effective detection mechanisms. The experience of analyzing real attack traffic and creating custom signatures gave me practical skills directly applicable to SOC analyst roles.

---

## 📸 Screenshots
 1. Demo IPS Signature ( https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%201.png?raw=true)
 2. Rule Validaton (https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%202.png?raw=true)
 3. Snort Startup (https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%203.png?raw=true)
 4. tested on local network adapter (https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%204.png?raw=true)
 5. PluginConfiguration(https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%205.png?raw=true)
 6. performance metrics(https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%206.png?raw=true)
 7. pcap forensics(https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%207.png?raw=true)
 8. pcap analysis command(https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%208.png?raw=true)
 9. continuation to threat analysis (https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%209.png?raw=true)
 10. sorted threats  , signature counts (https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%2010.png?raw=true)
 11. exploit attempt (https://github.com/aBdUl-AhaD02/Network-Intrusion-Detection-System/blob/main/Images/Screenshot%2011.png?raw=true)
 12. (images/secreenshot5.png)


## 📄 License

This project is for educational and research purposes.

---

## 👤 Author

**Abdul Ahad**
- LinkedIn: [linkedin.com/in/aabdulahadd](https://linkedin.com/in/aabdulahadd)
- Email: abdulahad02002@gmail.com
