# SSL VPN Checker

This Python script determines if a remote host is running an SSL VPN by analyzing its SSL certificate.

## Features

- Checks various SSL/TLS protocols to establish a secure connection
- Analyzes certificate extensions and fields for VPN indicators
- Supports both IP addresses and hostnames
- Customizable port number (default: 443)

## Requirements

- Python 3.6+
- cryptography library

## Installation

1. Clone this repository:
   git clone https://github.com/synfinner/ssl-vpn-checker.git
   cd ssl-vpn-checker

2. Install the required dependencies:
   `pip3 install -r requirements.txt`

## Usage

Run the script with either an IP address or a hostname:

`python amiavpn.py -i 192.168.1.1`

`python amiavpn.py -H example.com`

To specify a custom port:

`python amiavpn.py -H example.com -p 8443`

## VPN Indicators

The script checks for the following VPN indicators:

- Extended Key Usage (EKU) extension
- Certificate Policies (CP) extension
- Organizational Unit (OU) field
- Common Name (CN) field
- Key Usage extension
- Microsoft TLS/SSL Client Authentication OID

## Output

The script will display the results of each check and provide a conclusion on whether the certificate is likely to be an SSL VPN certificate.

```
./amiavpn.py -i xx.xx.xx.xx  -p xxxx
SSL VPN indicators for xx.xx.xx.xx:
  EKU (Extended Key Usage): CLIENT_AUTH, SERVER_AUTH
  CP (Certificate Policies): Not Found
  OU (Organizational Unit): Not Found
  CN (Common Name): Found
  Key Usage: Not Found
  MS TLS OID: Not Found
  Additional EKU: Server Authentication (1.3.6.1.5.5.7.3.1), Client Authentication (1.3.6.1.5.5.7.3.2)
  Custom Vendor OIDs:
    - Cisco AnyConnect: Not Found
    - Juniper Networks: Not Found
    - Fortinet: Not Found
    - Citrix NetScaler: Not Found
    - Check Point: Not Found
    - F5 Networks: Not Found
    - SonicWall: Not Found
    - Pulse Secure: Not Found
    - Sophos: Not Found
    - Palo Alto Networks GlobalProtect: Not Found
    - Server Authentication: Not Found
    - Client Authentication: Not Found
    - Code Signing: Not Found
    - Email Protection: Not Found
    - Time Stamping: Not Found
    - OCSP Signing: Not Found
    - Smart Card Logon: Not Found
    - VeriSign Class 3 Secure Server CA - G3: Not Found
    - VeriSign Class 3 Extended Validation SSL SGC CA: Not Found
    - Microsoft Document Signing: Not Found
    - EAP Over PPP: Not Found
    - EAP Over LAN: Not Found
  SAN (Subject Alternative Name): Not Found
  Issuer: Not Found
  Validity Period: 
  Fingerprint

The certificate for xx.xx.xx.xx is likely an SSL VPN certificate.
```

## Disclaimer

This tool is for educational and research purposes only. Always ensure you have permission before scanning or analyzing networks and systems you do not own or have explicit permission to test.