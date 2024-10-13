#!/usr/bin/env python3

"""
Python script to determine if a remote host is running an SSLVPN.
"""

import socket
import ssl
import cryptography
from cryptography import x509
import argparse
from dataclasses import dataclass, field
import warnings
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ObjectIdentifier
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, ObjectIdentifier
from typing import Dict
from cryptography.x509.extensions import SubjectAlternativeName
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes
from colorama import Fore, Style  # Import colorama for colored output

@dataclass
class VPNIndicators:
    eku: str = ""
    cp: bool = False
    ou: bool = False
    cn: bool = False
    ku: bool = False
    custom: bool = False
    san: bool = False
    issuer: bool = False
    serial: bool = False
    validity: bool = False
    additional_eku: str = ""
    custom_vendor_oid: Dict[str, bool] = field(default_factory=dict)
    validity_period: str = ""
    fingerprint: str = ""

class SSLVPNChecker:
    def __init__(self, address, port=443):
        self.address = address
        self.port = port
        self.cert = None

    def get_certificate(self):
        protocols = [
            ssl.PROTOCOL_TLSv1_2,
            ssl.PROTOCOL_TLSv1_1,
            ssl.PROTOCOL_TLSv1,
            ssl.PROTOCOL_SSLv23,  # Allows the highest protocol that both the client and server support
        ]

        for protocol in protocols:
            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=DeprecationWarning)
                    context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers('ALL:@SECLEVEL=0')  # Allow weak ciphers

                with socket.create_connection((self.address, self.port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.address) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        self.cert = x509.load_der_x509_certificate(der_cert)
                        return self.cert
            except (ssl.SSLError, socket.error) as e:
                print(f"Failed with {protocol}: {str(e)}")
                continue

        print(f"Unable to establish a secure connection to {self.address}")
        return None

    def check_certificate_validity(self):
        if not self.cert:
            return "Unknown"

        not_before = self.cert.not_valid_before_utc
        not_after = self.cert.not_valid_after_utc
        current_time = datetime.now(timezone.utc)

        if not_before > current_time:
            return "Certificate not valid yet."
        if not_after < current_time:
            return "Certificate has expired."
        
        self.indicators.validity_period = f"Valid from {not_before} to {not_after}"
        return "Certificate is currently valid."

    def check_san_extension(self):
        try:
            san_extension = self.cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_dns = san_extension.value.get_values_for_type(x509.DNSName)
            return san_dns  # Just return the SAN values
        except x509.ExtensionNotFound:
            return []  # Return an empty list if the extension is not found

    def check_issuer(self):
        # Return the issuer's string representation
        return self.cert.issuer.rfc4514_string()

    def compute_fingerprint(self):
        fingerprint = self.cert.fingerprint(hashes.SHA256()).hex()
        self.indicators.fingerprint = fingerprint

    def check_additional_indicators(self):
        self.check_san_extension()
        self.check_certificate_validity()
        self.check_issuer()
        self.compute_fingerprint()
        # Add more checks as needed

    def check_ssl_vpn(self):
        if not self.cert:
            return None

        indicators = VPNIndicators()
        self.indicators = indicators  # Assign to instance for use in additional methods
        
        # Check for EKU extension
        try:
            eku = self.cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
            eku_values = []
            if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku.value:
                eku_values.append("CLIENT_AUTH")
            if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku.value:
                eku_values.append("SERVER_AUTH")
            
            # Check for id-pkinit-KPClientAuth
            pkinit_client_auth_oid = ObjectIdentifier("1.3.6.1.5.2.3.4")
            if pkinit_client_auth_oid in eku.value:
                eku_values.append("PKINIT_CLIENT_AUTH")
            
            # Check for Entra Conditional Access
            entra_conditional_access_oid = ObjectIdentifier("1.3.6.1.4.1.311.87")
            if entra_conditional_access_oid in eku.value:
                eku_values.append("ENTRA_CONDITIONAL_ACCESS")
            
            if eku_values:
                indicators.eku = ", ".join(eku_values)
            else:
                indicators.eku = "No relevant EKU values found"
        except x509.ExtensionNotFound:
            indicators.eku = "Extension not found"
        try:
            eku = self.cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_values = [eku_oid.dotted_string for eku_oid in eku.value]
            # Add specific EKUs
            if ExtendedKeyUsageOID.CODE_SIGNING in eku.value:
                eku_values.append("CODE_SIGNING")
            if ExtendedKeyUsageOID.EMAIL_PROTECTION in eku.value:
                eku_values.append("EMAIL_PROTECTION")
            indicators.additional_eku = ", ".join(eku_values) if eku_values else "No additional EKU values found"
        except x509.ExtensionNotFound:
            indicators.additional_eku = "Extension not found"

        # Check for custom/vendor-specific OIDs
        custom_oids = {
            # Vendor-Specific OIDs
            "1.3.6.1.4.1.9.9.168.1.1": "Cisco AnyConnect",
            "1.3.6.1.4.1.2636.3.1": "Juniper Networks",
            "1.3.6.1.4.1.12356.101.1.1": "Fortinet",
            "1.3.6.1.4.1.5951.4.1.1": "Citrix NetScaler",
            "1.3.6.1.4.1.2620.1.1.0": "Check Point",
            "1.3.6.1.4.1.3375.2.3": "F5 Networks",
            "1.3.6.1.4.1.311.89.3.3.1": "SonicWall",
            "1.3.6.1.4.1.534.1.1": "Pulse Secure",
            "1.3.6.1.4.1.22554.1.1.1": "Sophos",
            "1.3.6.1.4.1.12605.1.2.1": "Palo Alto Networks GlobalProtect",
            
            # Extended Key Usage OIDs
            "1.3.6.1.5.5.7.3.1": "Server Authentication",
            "1.3.6.1.5.5.7.3.2": "Client Authentication",
            "1.3.6.1.5.5.7.3.3": "Code Signing",
            "1.3.6.1.5.5.7.3.4": "Email Protection",
            "1.3.6.1.5.5.7.3.8": "Time Stamping",
            "1.3.6.1.5.5.7.3.9": "OCSP Signing",
            "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
            
            # Certificate Policies OIDs
            "2.16.840.1.113733.1.7.23.6": "VeriSign Class 3 Secure Server CA - G3",
            "2.16.840.1.113733.1.7.23.7": "VeriSign Class 3 Extended Validation SSL SGC CA",
            
            # Microsoft-Specific OIDs
            "1.3.6.1.4.1.311.10.3.12": "Microsoft Document Signing",
            
            # Other Security-Related OIDs
            "1.3.6.1.5.5.7.3.14": "EAP Over PPP",
            "1.3.6.1.5.5.7.3.13": "EAP Over LAN",
        }
        for oid, vendor in custom_oids.items():
            try:
                self.cert.extensions.get_extension_for_oid(ObjectIdentifier(oid))
                indicators.custom_vendor_oid[vendor] = True
            except x509.ExtensionNotFound:
                indicators.custom_vendor_oid[vendor] = False

        # Check for CP extension
        try:
            cp = self.cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CERTIFICATE_POLICIES)
            indicators.cp = any(
                policy.policy_identifier.dotted_string in ['2.16.840.1.113733.1.7.23.6', '2.16.840.1.113733.1.7.23.7']
                for policy in cp.value
            )
        except x509.ExtensionNotFound:
            indicators.cp = False

        # Check for OU field
        ou = self.cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)
        indicators.ou = any('ssl vpn' in attr.value.lower() or 'vpn server' in attr.value.lower() for attr in ou)

        # Check for CN field
        cn = self.cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        indicators.cn = any('vpn' in attr.value.lower() for attr in cn)

        # Check for Key Usage extension
        try:
            ku = self.cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
            indicators.ku = ku.value.digital_signature and ku.value.key_encipherment
        except x509.ExtensionNotFound:
            indicators.ku = False

        custom_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1") # Microsoft TLS/SSL Client Authentication OID
        try:
            custom_ext = self.cert.extensions.get_extension_for_oid(custom_oid)
            indicators.custom = True
        except x509.ExtensionNotFound:
            indicators.custom = False

        # Additional EKU checks
        try:
            eku = self.cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_values = []
            
            # Mapping of known EKU OIDs to their names
            eku_oid_map = {
                ExtendedKeyUsageOID.SERVER_AUTH: "Server Authentication",
                ExtendedKeyUsageOID.CLIENT_AUTH: "Client Authentication",
                ExtendedKeyUsageOID.CODE_SIGNING: "Code Signing",
                ExtendedKeyUsageOID.EMAIL_PROTECTION: "Email Protection",
                ExtendedKeyUsageOID.TIME_STAMPING: "Time Stamping",
                ExtendedKeyUsageOID.OCSP_SIGNING: "OCSP Signing",
                ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"): "Smart Card Logon",
                ObjectIdentifier("1.3.6.1.5.5.7.3.14"): "EAP Over PPP",
                ObjectIdentifier("1.3.6.1.5.5.7.3.13"): "EAP Over LAN",
                ObjectIdentifier("1.3.6.1.4.1.311.10.3.12"): "Document Signing",
            }

            for eku_oid in eku.value:
                oid_string = eku_oid.dotted_string
                eku_name = eku_oid_map.get(eku_oid, "Unknown")
                eku_values.append(f"{eku_name} ({oid_string})")

            indicators.additional_eku = ", ".join(eku_values) if eku_values else "No additional EKU values found"
        except x509.ExtensionNotFound:
            indicators.additional_eku = "Extension not found"

        # Check for SAN extension
        indicators.san = self.check_san_extension()  # Store SAN values

        # Check for issuer
        indicators.issuer = self.check_issuer()  # Store issuer information

        # Perform additional checks
        self.check_additional_indicators()

        return indicators

def parse_arguments():
    parser = argparse.ArgumentParser(description="Determine if a remote host is running an SSLVPN.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="IP address to check")
    group.add_argument("-H", "--hostname", help="Hostname to check")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port number (default: 443)")
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    address = args.ip if args.ip else args.hostname
    checker = SSLVPNChecker(address, args.port)
    
    if not checker.get_certificate():
        print("Unable to retrieve certificate")
        return

    indicators = checker.check_ssl_vpn()
    if indicators:
        print(f"SSL VPN indicators for {address}:")
        # Updated EKU output to be bold green if values are present
        eku_output = indicators.eku if indicators.eku else "No relevant EKU values found"
        print(f"  EKU (Extended Key Usage): {Fore.GREEN + eku_output + Style.RESET_ALL if indicators.eku else Fore.RED + 'Not Found' + Style.RESET_ALL}")  # Updated
        print(f"  CP (Certificate Policies): {Fore.GREEN + 'Found' + Style.RESET_ALL if indicators.cp else Fore.RED + 'Not Found' + Style.RESET_ALL}")  # Updated
        print(f"  OU (Organizational Unit): {Fore.GREEN + 'Found' + Style.RESET_ALL if indicators.ou else Fore.RED + 'Not Found' + Style.RESET_ALL}")  # Updated
        print(f"  CN (Common Name): {Fore.GREEN + 'Found' + Style.RESET_ALL if indicators.cn else Fore.RED + 'Not Found' + Style.RESET_ALL}")  # Updated
        print(f"  Key Usage: {Fore.GREEN + 'Found' + Style.RESET_ALL if indicators.ku else Fore.RED + 'Not Found' + Style.RESET_ALL}")  # Updated
        print(f"  MS TLS OID: {Fore.GREEN + 'Found' + Style.RESET_ALL if indicators.custom else Fore.RED + 'Not Found' + Style.RESET_ALL}")  # Updated
        print(f"  Additional EKU: {indicators.additional_eku}")
        print("  Custom Vendor OIDs:")
        for vendor, found in indicators.custom_vendor_oid.items():
            print(f"    - {vendor}: {Fore.GREEN + 'Found' + Style.RESET_ALL if found else Fore.RED + 'Not Found' + Style.RESET_ALL}")  # Updated
        print(f"  SAN (Subject Alternative Name): {Fore.GREEN + 'Found' + Style.RESET_ALL if indicators.san else Fore.RED + 'Not Found' + Style.RESET_ALL}")  # Updated
        print(f"  Issuer: {indicators.issuer if indicators.issuer else Fore.RED + 'Not Found' + Style.RESET_ALL}")  # Updated
        print(f"  Validity Period: {indicators.validity_period}")
        print(f"  Fingerprint: {indicators.fingerprint}")
        
        if any(vars(indicators).values()):
            print(f"\nThe certificate for {address} is likely an SSL VPN certificate.")
        else:
            print(f"\nThe certificate for {address} does not appear to be an SSL VPN certificate.")
    else:
        print("Unable to check SSL VPN indicators")

if __name__ == "__main__":
    from colorama import init
    init(autoreset=True)  # Initialize colorama
    main()