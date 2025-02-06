# Net Phantom IP Address Checker

A Python based IP address analysis tool that provides detailed information about IP addresses and domains. This tool fetches and analyzes various aspects of an IP address or domain, including geolocation, network information, DNS records, SSL certificates, WHOIS data, and port scanning.

## 🌟 Features

### Core Functionality
- IPv4 and IPv6 support
- Domain name resolution
- Response time measurement
- Detailed geolocation data
- Network information analysis

### Advanced Information Gathering
- **DNS Analysis**
  - Multiple record types (A, AAAA, MX, NS, TXT, SOA, CNAME)
  - Nameserver information
  - Reverse DNS lookup

- **Security Information**
  - SSL/TLS certificate details
  - Port scanning with service detection
  - Banner grabbing for open ports
  - Proxy/VPN detection

- **Domain Information**
  - WHOIS data retrieval
  - Registration details
  - Domain status
  - Registrar information

### Data Management
- Organized data storage in `dataV/` directory
- Raw data storage in JSON format
- Interactive visualizations
- Historical data viewing
- Structured report generation

## 📋 Requirements

- Python 3.7+
- Required packages:
  ```
  requests
  dnspython
  python-whois
  pyOpenSSL
  plotly
  pandas
  ```

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rexzea/Net-Phantom.git
   ```

2. Navigate folder
   ```bash
   cd Net-Phantom
   ```

3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

Run the program:
```bash
python ip_checker.py
```

The program offers three main options:
1. Check IP address or hostname
2. View previous search results
3. Exit

### Example Usage:

```bash


 ███▄    █ ▓█████ ▄▄▄█████▓    ██▓███   ██░ ██  ▄▄▄       ███▄    █ ▄▄▄█████▓ ▒█████   ███▄ ▄███▓
 ██ ▀█   █ ▓█   ▀ ▓  ██▒ ▓▒   ▓██░  ██▒▓██░ ██▒▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒▒██▒  ██▒▓██▒▀█▀ ██▒
▓██  ▀█ ██▒▒███   ▒ ▓██░ ▒░   ▓██░ ██▓▒▒██▀▀██░▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░▒██░  ██▒▓██    ▓██░
▓██▒  ▐▌██▒▒▓█  ▄ ░ ▓██▓ ░    ▒██▄█▓▒ ▒░▓█ ░██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██   ██░▒██    ▒██
▒██░   ▓██░░▒████▒  ▒██▒ ░    ▒██▒ ░  ░░▓█▒░██▓ ▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ ░ ████▓▒░▒██▒   ░██▒
░ ▒░   ▒ ▒ ░░ ▒░ ░  ▒ ░░      ▒▓▒░ ░  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒░   ░  ░
░ ░░   ░ ▒░ ░ ░  ░    ░       ░▒ ░      ▒ ░▒░ ░  ▒   ▒▒ ░░ ░░   ░ ▒░    ░      ░ ▒ ▒░ ░  ░      ░
   ░   ░ ░    ░     ░         ░░        ░  ░░ ░  ░   ▒      ░   ░ ░   ░      ░ ░ ░ ▒  ░      ░
         ░    ░  ░                      ░  ░  ░      ░  ░         ░              ░ ░         ░


cr : Rexzea

```

```bash
# Check an IP address
Enter IP address or hostname (example: 8.8.8.8 or google.com): 8.8.8.8

# View results in dataV/ directory:
- Raw data: /raw/
- Visualizations: /visualizations/
- Reports: /reports/
```


#### Result
```bash

Basic Information:
IP Address: 8.8.8.8
Response Time: 0.373 detik
Tipe: Non-Mobile
Proxy/VPN: Tidak
Hosting/Datacenter: Ya

Location:
Continent: North America (NA)
Country: United States (US)
Region: Virginia (VA)
City: Ashburn
District:
Zip Code: 20149
Coordinate: 39.03, -77.5

Network Network:
ISP: Google LLC
Organization: Google Public DNS
AS Number: AS15169 Google LLC
AS Name: GOOGLE
Reverse DNS: dns.google

DNS Information:
Record DNS:
- A: 8.8.4.4, 8.8.8.8
- AAAA: 2001:4860:4860::8888, 2001:4860:4860::8844
- NS: ns4.zdns.google., ns3.zdns.google., ns2.zdns.google., ns1.zdns.google.
- TXT: "v=spf1 -all", "https://xkcd.com/1361/"
- SOA: ns1.zdns.google. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300
Nameservers: ns3.zdns.google., ns2.zdns.google., ns1.zdns.google., ns4.zdns.google.

SSL Information:
Issuer: [(b'C', b'US'), (b'O', b'Google Trust Services'), (b'CN', b'WR2')]
Subject: [(b'CN', b'dns.google')]
Valid From: b'20250106083801Z'
Valid Until: b'20250331083800Z'
Version: 2

WHOIS Information:
Registrar: MarkMonitor Inc.
Created: 2018-04-16 22:57:01
Expires: 2025-04-16 22:57:01
Updated: 2024-03-20 10:02:54
Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited, clientTransferProhibited https://icann.org/epp#clientTransferProhibited, clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Nameservers: ns1.zdns.google, ns2.zdns.google, ns3.zdns.google, ns4.zdns.google
```


## 📁 Directory Structure

```
dataV/
├── raw/           # Raw JSON data
├── reports/       # Formatted reports
├── visualizations/# Interactive visualizations
└── history/       # Search history
```

## 📊 Output Information

The tool provides information including:
- Basic IP information
- Geographical data
- Network details
- DNS records
- SSL certificate information
- WHOIS data
- Port scan results
- Response times

## 🔍 Features in Detail

### Geolocation Information
- Continent and country
- Region and city
- District and postal code
- Precise coordinates

### Network Analysis
- ISP details
- Organization information
- AS number and name
- Connection type

### Security Scanning
- Common port scanning
- Service detection
- SSL certificate analysis
- Security flags (proxy/VPN/hosting detection)

## 🛠 Technical Details

- Multithreaded data collection
- Robust error handling
- Timeout management
- Data validation
- Structured data storage
- Interactive visualizations

## ⚠️ Error Handling

The program includes comprehensive error handling for:
- Invalid IP addresses
- Network failures
- API timeouts
- Invalid data responses
- DNS resolution failures

## 📈 Visualization

Port scan results are visualized using Plotly, creating interactive HTML charts showing:
- Open/closed ports
- Service information
- Port status distribution

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [ip-api.com](http://ip-api.com) for IP geolocation data
- Various open-source Python packages that made this project possible

## ⚡ Future Improvements

- Add support for batch processing
- Implement rate limiting for API calls
- Add more visualization types
- Create export options for different formats
- Add command-line interface
- Implement caching system


## 📞 Support & Contact
Need assistance? Reach out through:
- 📧 Email: [futzfary@gmail.com](mailto:futzfary@gmail.com)
- 📱 Phone: +62 898-8610-455
- 💬 GitHub Issues: Open a new issue in the repository

<div align="center">

![Logo Python](https://upload.wikimedia.org/wikipedia/commons/c/c3/Python-logo-notext.svg)

```
🌟 Crafted with ❤️ by Rexzea 🌟
```
</div>

---

<div align="center">

### Show Your Support
⭐ Star this repository if you find it helpful! ⭐

[Report Bug](https://github.com/rexzea/Net-Phantom/issues) · [Request Feature](https://github.com/rexzea/Net-Phantom/issues)
