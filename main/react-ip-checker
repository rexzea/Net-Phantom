import requests
import re
import json
from typing import Optional, Dict, Union, List, Tuple
from datetime import datetime
import socket
import time
import os
from dataclasses import dataclass
from enum import Enum
import csv
import plotly.graph_objects as go
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import whois
import ssl
import OpenSSL
from urllib.parse import urlparse
import dns.resolver
import threading
import queue

class IPVersion(Enum):
    IPv4 = "IPv4"
    IPv6 = "IPv6"
    INVALID = "Invalid"

@dataclass
class DNSInfo:
    records: Dict[str, List[str]]
    nameservers: List[str]
    errors: List[str]

@dataclass
class SSLInfo:
    valid: bool
    issuer: str
    subject: str
    valid_from: str
    valid_until: str
    version: str
    serial_number: str
    errors: List[str]

@dataclass
class WhoisInfo:
    registrar: str
    creation_date: str
    expiration_date: str
    updated_date: str
    status: List[str]
    name_servers: List[str]
    errors: List[str]

@dataclass
class PortInfo:
    port: int
    status: str
    service: str
    banner: Optional[str]

@dataclass
class IPValidationResult:
    is_valid: bool
    version: IPVersion
    error_message: Optional[str] = None

class IPInfo:
    def __init__(self, data: dict):
        # Basic Info
        self.ip = data.get('query', 'Not available')
        self.status = data.get('status', 'fail')
        
        # Geographic Info
        self.continent = data.get('continent', 'Not available')
        self.continent_code = data.get('continentCode', 'Not available')
        self.country = data.get('country', 'Not available')
        self.country_code = data.get('countryCode', 'Not available')
        self.region = data.get('regionName', 'Not available')
        self.region_code = data.get('region', 'Not available')
        self.city = data.get('city', 'Not available')
        self.district = data.get('district', 'Not available')
        self.zip_code = data.get('zip', 'Not available')
        self.latitude = data.get('lat', 'Not available')
        self.longitude = data.get('lon', 'Not available')
        
        # Network Info
        self.timezone = data.get('timezone', 'Not available')
        self.offset = data.get('offset', 'Not available')
        self.currency = data.get('currency', 'Not available')
        self.isp = data.get('isp', 'Not available')
        self.org = data.get('org', 'Not available')
        self.as_number = data.get('as', 'Not available')
        self.as_name = data.get('asname', 'Not available')
        self.reverse_dns = data.get('reverse', 'Not available')
        
        self.mobile = data.get('mobile', False)
        self.proxy = data.get('proxy', False)
        self.hosting = data.get('hosting', False)
        
        self.dns_info: Optional[DNSInfo] = None
        self.ssl_info: Optional[SSLInfo] = None
        self.whois_info: Optional[WhoisInfo] = None
        self.port_scan: List[PortInfo] = []
        self.response_time: float = 0.0
        self.trace_route: List[str] = []

class IPChecker:
    def __init__(self):
        self.base_url = "http://ip-api.com/json/"
        self.fields = "status,message,continent,continentCode,country,countryCode," \
                     "region,regionName,city,district,zip,lat,lon,timezone,offset," \
                     "currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        self.max_retries = 3
        self.retry_delay = 2
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
        self.dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        #make folder
        self.data_dir = "dataV"
        self.setup_directories()

    def setup_directories(self):
        directories = [
            self.data_dir,
            f"{self.data_dir}/raw",
            f"{self.data_dir}/reports",
            f"{self.data_dir}/visualizations",
            f"{self.data_dir}/history"
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def get_dns_info(self, domain: str) -> DNSInfo:
        records = {}
        errors = []
        nameservers = []

        for record_type in self.dns_record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except Exception as e:
                errors.append(f"Error getting {record_type} record: {str(e)}")

        try:
            ns_answers = dns.resolver.resolve(domain, 'NS')
            nameservers = [str(ns) for ns in ns_answers]
        except Exception as e:
            errors.append(f"Error getting nameservers: {str(e)}")

        return DNSInfo(records, nameservers, errors)

    def get_ssl_info(self, domain: str, port: int = 443) -> SSLInfo:
        errors = []
        try:
            cert = ssl.get_server_certificate((domain, port))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            return SSLInfo(
                valid=True,
                issuer=str(x509.get_issuer().get_components()),
                subject=str(x509.get_subject().get_components()),
                valid_from=str(x509.get_notBefore()),
                valid_until=str(x509.get_notAfter()),
                version=str(x509.get_version()),
                serial_number=str(x509.get_serial_number()),
                errors=errors
            )
        except Exception as e:
            errors.append(str(e))
            return SSLInfo(
                valid=False,
                issuer="Unknown",
                subject="Unknown",
                valid_from="Unknown",
                valid_until="Unknown",
                version="Unknown",
                serial_number="Unknown",
                errors=errors
            )

    def scan_port(self, ip: str, port: int) -> PortInfo:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        
        try:
            start_time = time.time()
            result = sock.connect_ex((ip, port))
            response_time = time.time() - start_time
            
            status = "Open" if result == 0 else "Closed"
            service = socket.getservbyport(port) if status == "Open" else "Unknown"
            banner = None
            
            if status == "Open":
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
                    
            return PortInfo(port, status, service, banner)
        except:
            return PortInfo(port, "Error", "Unknown", None)
        finally:
            sock.close()

    def get_whois_info(self, domain: str) -> WhoisInfo:
        errors = []
        try:
            w = whois.whois(domain)
            return WhoisInfo(
                registrar=str(w.registrar),
                creation_date=str(w.creation_date),
                expiration_date=str(w.expiration_date),
                updated_date=str(w.updated_date),
                status=[str(s) for s in w.status] if isinstance(w.status, list) else [str(w.status)],
                name_servers=[str(ns) for ns in w.name_servers] if isinstance(w.name_servers, list) else [str(w.name_servers)],
                errors=errors
            )
        except Exception as e:
            errors.append(str(e))
            return WhoisInfo(
                registrar="Unknown",
                creation_date="Unknown",
                expiration_date="Unknown",
                updated_date="Unknown",
                status=[],
                name_servers=[],
                errors=errors
            )

    def trace_route(self, ip: str) -> List[str]:
        trace = []
        try:
            for ttl in range(1, 31):
                pass  #detail trace
        except Exception as e:
            trace.append(f"Error in trace route: {str(e)}")
        return trace

    def validate_ip(self, ip: str) -> IPValidationResult:
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ipv6_pattern = r'^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'

        try:
            if not re.match(ipv4_pattern, ip) and not re.match(ipv6_pattern, ip):
                ip = socket.gethostbyname(ip)

            if re.match(ipv4_pattern, ip):
                return IPValidationResult(True, IPVersion.IPv4)
            elif re.match(ipv6_pattern, ip):
                return IPValidationResult(True, IPVersion.IPv6)
            else:
                return IPValidationResult(False, IPVersion.INVALID, "Format IP address tidak valid")
        except socket.gaierror:
            return IPValidationResult(False, IPVersion.INVALID, "Hostname tidak valid atau tidak dapat di-resolve")
        except Exception as e:
            return IPValidationResult(False, IPVersion.INVALID, f"Error validasi: {str(e)}")

    def get_ip_info(self, ip: str) -> Optional[IPInfo]:
        validation_result = self.validate_ip(ip)
        if not validation_result.is_valid:
            print(f"\nError: {validation_result.error_message}")
            return None

        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                url = f"{self.base_url}{ip}?fields={self.fields}"
                response = requests.get(url, timeout=10)
                response_time = time.time() - start_time
                
                response.raise_for_status()
                data = response.json()

                if data.get("status") == "fail":
                    print(f"\nError: {data.get('message', 'Unknown error')}")
                    return None

                ip_info = IPInfo(data)
                ip_info.response_time = response_time

                with ThreadPoolExecutor(max_workers=4) as executor:
                    if ip_info.reverse_dns != "Not available":
                                dns_future = executor.submit(self.get_dns_info, ip_info.reverse_dns)
                                ssl_future = executor.submit(self.get_ssl_info, ip_info.reverse_dns)
                                whois_future = executor.submit(self.get_whois_info, ip_info.reverse_dns)
                                
                                try:
                                    ip_info.dns_info = dns_future.result(timeout=10)
                                except Exception as e:
                                    print(f"Error getting DNS info: {str(e)}")
                                    ip_info.dns_info = DNSInfo({}, [], [str(e)])

                                try:
                                    ip_info.ssl_info = ssl_future.result(timeout=10)
                                except Exception as e:
                                    print(f"Error getting SSL info: {str(e)}")
                                    ip_info.ssl_info = SSLInfo(False, "Unknown", "Unknown", "Unknown", 
                                                             "Unknown", "Unknown", "Unknown", [str(e)])

                                try:
                                    ip_info.whois_info = whois_future.result(timeout=10)
                                except Exception as e:
                                    print(f"Error getting WHOIS info: {str(e)}")
                                    ip_info.whois_info = WhoisInfo("Unknown", "Unknown", "Unknown", 
                                                                 "Unknown", [], [], [str(e)])

                           
                self.save_raw_data(ip_info)
                
                self.create_visualizations(ip_info)
                
                return ip_info

            except requests.exceptions.Timeout:
                print(f"\nTimeout on attempt -{attempt + 1}")
            except requests.exceptions.RequestException as e:
                print(f"\nNetwork error on test -{attempt + 1}: {str(e)}")
            except json.JSONDecodeError:
                print(f"\nError:Failed to process response from server on attempt -{attempt + 1}")
            except Exception as e:
                print(f"\nError unexpected on the -{attempt + 1}: {str(e)}")

            if attempt < self.max_retries - 1:
                print(f"Try going back in {self.retry_delay} second...")
                time.sleep(self.retry_delay)

        print("\nFailed to get information after several attempts")
        return None

    def save_raw_data(self, ip_info: IPInfo):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.data_dir}/raw/ip_info_{ip_info.ip}_{timestamp}.json"
        
        data = {
            'timestamp': timestamp,
            'ip': ip_info.ip,
            'basic_info': {
                'continent': ip_info.continent,
                'country': ip_info.country,
                'region': ip_info.region,
                'city': ip_info.city,
                'coordinates': [ip_info.latitude, ip_info.longitude]
            },
            'network_info': {
                'isp': ip_info.isp,
                'org': ip_info.org,
                'as_number': ip_info.as_number,
                'as_name': ip_info.as_name
            },
            'dns_info': vars(ip_info.dns_info) if ip_info.dns_info else None,
            'ssl_info': vars(ip_info.ssl_info) if ip_info.ssl_info else None,
            'whois_info': vars(ip_info.whois_info) if ip_info.whois_info else None,
            'port_scan': [vars(port) for port in ip_info.port_scan],
            'response_time': ip_info.response_time
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def create_visualizations(self, ip_info: IPInfo):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if ip_info.port_scan:
            fig = go.Figure(data=[
                go.Bar(
                    x=[str(port.port) for port in ip_info.port_scan],
                    y=[1 if port.status == "Open" else 0 for port in ip_info.port_scan],
                    text=[f"{port.service}<br>{port.status}" for port in ip_info.port_scan],
                    hoverinfo="text"
                )
            ])
            
            fig.update_layout(
                title=f"Port Scan Results for {ip_info.ip}",
                xaxis_title="Port Number",
                yaxis_title="Status (1=Open, 0=Closed)",
                template="plotly_dark"
            )
            
            fig.write_html(f"{self.data_dir}/visualizations/port_scan_{ip_info.ip}_{timestamp}.html")

    def format_output(self, ip_info: IPInfo) -> str:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        sections = [
            "=" * 50,
            f"IP Address Search Results (per {current_time})",
            "=" * 50,
            
            "\nBasic Information:",
            f"IP Address: {ip_info.ip}",
            f"Response Time: {ip_info.response_time:.3f} detik",
            f"Tipe: {'Mobile' if ip_info.mobile else 'Non-Mobile'}",
            f"Proxy/VPN: {'Ya' if ip_info.proxy else 'Tidak'}",
            f"Hosting/Datacenter: {'Ya' if ip_info.hosting else 'Tidak'}",
            
            "\nLokasi:",
            f"Continent: {ip_info.continent} ({ip_info.continent_code})",
            f"Country: {ip_info.country} ({ip_info.country_code})",
            f"Region: {ip_info.region} ({ip_info.region_code})",
            f"City: {ip_info.city}",
            f"District: {ip_info.district}",
            f"Zip Code: {ip_info.zip_code}",
            f"Coordinate: {ip_info.latitude}, {ip_info.longitude}",
            
            "\nInformasi Network:",
            f"ISP: {ip_info.isp}",
            f"Organization: {ip_info.org}",
            f"AS Number: {ip_info.as_number}",
            f"AS Name: {ip_info.as_name}",
            f"Reverse DNS: {ip_info.reverse_dns}"
        ]
        
        if ip_info.dns_info:
            sections.extend([
                "\nInformasi DNS:",
                "Record DNS:"
            ])
            for record_type, records in ip_info.dns_info.records.items():
                sections.append(f"- {record_type}: {', '.join(records)}")
            sections.append(f"Nameservers: {', '.join(ip_info.dns_info.nameservers)}")
        
        if ip_info.ssl_info and ip_info.ssl_info.valid:
            sections.extend([
                "\nSSL Information:",
                f"Issuer: {ip_info.ssl_info.issuer}",
                f"Subject: {ip_info.ssl_info.subject}",
                f"Valid From: {ip_info.ssl_info.valid_from}",
                f"Valid Until: {ip_info.ssl_info.valid_until}",
                f"Version: {ip_info.ssl_info.version}"
            ])
        
        if ip_info.whois_info:
            sections.extend([
                "\nWHOIS Information:",
                f"Registrar: {ip_info.whois_info.registrar}",
                f"Created: {ip_info.whois_info.creation_date}",
                f"Expires: {ip_info.whois_info.expiration_date}",
                f"Updated: {ip_info.whois_info.updated_date}",
                f"Status: {', '.join(ip_info.whois_info.status)}",
                f"Nameservers: {', '.join(ip_info.whois_info.name_servers)}"
            ])
        
        if ip_info.port_scan:
            sections.extend([
                "\nPort Scan Information Result:",
                "Port\tStatus\tService\tBanner"
            ])
            for port_info in ip_info.port_scan:
                banner = port_info.banner[:50] + "..." if port_info.banner else "N/A"
                sections.append(f"{port_info.port}\t{port_info.status}\t{port_info.service}\t{banner}")
        
        return "\n".join(sections)

def main():
    print("=" * 50)
    print("""
 ███▄    █ ▓█████ ▄▄▄█████▓    ██▓███   ██░ ██  ▄▄▄       ███▄    █ ▄▄▄█████▓ ▒█████   ███▄ ▄███▓
 ██ ▀█   █ ▓█   ▀ ▓  ██▒ ▓▒   ▓██░  ██▒▓██░ ██▒▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒▒██▒  ██▒▓██▒▀█▀ ██▒
▓██  ▀█ ██▒▒███   ▒ ▓██░ ▒░   ▓██░ ██▓▒▒██▀▀██░▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░▒██░  ██▒▓██    ▓██░
▓██▒  ▐▌██▒▒▓█  ▄ ░ ▓██▓ ░    ▒██▄█▓▒ ▒░▓█ ░██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██   ██░▒██    ▒██ 
▒██░   ▓██░░▒████▒  ▒██▒ ░    ▒██▒ ░  ░░▓█▒░██▓ ▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ ░ ████▓▒░▒██▒   ░██▒
░ ▒░   ▒ ▒ ░░ ▒░ ░  ▒ ░░      ▒▓▒░ ░  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒░   ░  ░
░ ░░   ░ ▒░ ░ ░  ░    ░       ░▒ ░      ▒ ░▒░ ░  ▒   ▒▒ ░░ ░░   ░ ▒░    ░      ░ ▒ ▒░ ░  ░      ░
   ░   ░ ░    ░     ░         ░░        ░  ░░ ░  ░   ▒      ░   ░ ░   ░      ░ ░ ░ ▒  ░      ░   
         ░    ░  ░                      ░  ░  ░      ░  ░         ░              ░ ░         ░   
                                                                                                 
""")
    print("cr : Rexzea")
    print("=" * 50)
    
    checker = IPChecker()
    
    while True:
        print("\nPlease select an option:")
        print("1. Check the IP address or hostname")
        print("2. see previous search results")
        print("3. Exit")
        
        choice = input("\nYour choice (1/2/3): ").strip()
        
        if choice == "3":
            print("\nThank you for using Net Phantom IP Checker!")
            break
        elif choice == "1":
            ip = input("\nEnter the IP address or hostname (example: 8.8.8.8 or google.com): ").strip()
            
            print("\nRetrieve information (this may take a while)...")
            ip_info = checker.get_ip_info(ip)
            
            if ip_info:
                print(checker.format_output(ip_info))
                
                print(f"\nComplete results have been saved in a folder '{checker.data_dir}':")
                print(f"- Raw data: /raw/")
                print(f"- Visualization: /visualizations/")
                print(f"- Report: /reports/")
                
        elif choice == "2":
            raw_files = os.listdir(f"{checker.data_dir}/raw")
            if not raw_files:
                print("\nThere are no search results saved yet.")
                continue
                
            print("\nPrevious search results:")
            for i, file in enumerate(raw_files, 1):
                print(f"{i}. {file}")
            
            try:
                file_num = int(input("\nEnter the file number you want to view (0 to return): "))
                if file_num == 0:
                    continue
                if 1 <= file_num <= len(raw_files):
                    with open(f"{checker.data_dir}/raw/{raw_files[file_num-1]}", 'r') as f:
                        data = json.load(f)
                        print(json.dumps(data, indent=2, ensure_ascii=False))
                else:
                    print("\nInvalid file number!")
            except ValueError:
                print("\nInvalid input!")
        else:
            print("\nInvalid choice! Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()