import requests
import json
import whois
import shodan
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
import ipaddress
import logging
from pathlib import Path
import os
from dotenv import load_dotenv  

# make folder
data_dir = Path('data')                  
data_dir.mkdir(exist_ok=True)

# make subfolder
results_dir = data_dir / 'results'
logs_dir = data_dir / 'logs'
db_dir = data_dir / 'db'

for directory in [results_dir, logs_dir, db_dir]:
    directory.mkdir(exist_ok=True)

# load environment variables
load_dotenv()

# logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / 'ip_checker.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class IPThreatInfo:
    is_malicious: bool
    confidence_score: int
    recent_reports: int
    categories: List[str]
    last_reported: Optional[str]

@dataclass
class IPOwnerInfo:
    organization: str
    name: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    address: Optional[str]
    created_date: Optional[str]
    updated_date: Optional[str]

@dataclass
class IPDeviceInfo:
    hostname: Optional[str]
    ports: List[int]
    services: List[str]
    os: Optional[str]
    vulns: List[str]

@dataclass
class IPLocationHistory:
    timestamp: datetime
    country: str
    city: str
    latitude: float
    longitude: float

class SourceIpChecker:
    def __init__(self):
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.shodan_key = os.getenv('SHODAN_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.db_path = db_dir / 'ip_history.db'
        self.initialize_database()

    def initialize_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS ip_history
            (ip TEXT, timestamp TEXT, country TEXT, city TEXT,
             latitude REAL, longitude REAL)
        ''')
        conn.commit()
        conn.close()

    def validate_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    async def get_whois_info(self, ip: str) -> Optional[IPOwnerInfo]:
        try:
            w = whois.whois(ip)
            return IPOwnerInfo(
                organization=w.org or "Not available",
                name=w.name,
                email=w.emails[0] if w.emails else None,
                phone=w.phones[0] if w.phones else None,
                address=w.address,
                created_date=str(w.creation_date) if w.creation_date else None,
                updated_date=str(w.updated_date) if w.updated_date else None
            )
        except Exception as e:
            logging.error(f"Error getting WHOIS info: {str(e)}")
            return None

    async def check_threat_status(self, ip: str) -> Optional[IPThreatInfo]:
        if not self.abuseipdb_key:
            logging.warning("AbuseIPDB API key not configured")
            return None

        try:
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                headers=headers
            )
            data = response.json()['data']
            
            return IPThreatInfo(
                is_malicious=data['abuseConfidenceScore'] > 50,
                confidence_score=data['abuseConfidenceScore'],
                recent_reports=data['totalReports'],
                categories=data['reports'] if 'reports' in data else [],
                last_reported=data.get('lastReportedAt')
            )
        except Exception as e:
            logging.error(f"Error checking threat status: {str(e)}")
            return None

    async def get_device_info(self, ip: str) -> Optional[IPDeviceInfo]:
        if not self.shodan_key:
            logging.warning("Shodan API key not configured")
            return None

        try:
            api = shodan.Shodan(self.shodan_key)
            result = api.host(ip)
            
            return IPDeviceInfo(
                hostname=result.get('hostname'),
                ports=result.get('ports', []),
                services=[service['product'] for service in result.get('data', []) if 'product' in service],
                os=result.get('os'),
                vulns=result.get('vulns', [])
            )
        except Exception as e:
            logging.error(f"Error getting device info: {str(e)}")
            return None

    def store_location_history(self, ip: str, location_info: dict):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                INSERT INTO ip_history (ip, timestamp, country, city, latitude, longitude)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                ip,
                datetime.now().isoformat(),
                location_info['country'],
                location_info['city'],
                location_info['latitude'],
                location_info['longitude']
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Error storing location history: {str(e)}")

    def get_location_history(self, ip: str) -> List[IPLocationHistory]:
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            results = c.execute('''
                SELECT timestamp, country, city, latitude, longitude
                FROM ip_history
                WHERE ip = ?
                ORDER BY timestamp DESC
            ''', (ip,))
            
            history = []
            for row in results:
                history.append(IPLocationHistory(
                    timestamp=datetime.fromisoformat(row[0]),
                    country=row[1],
                    city=row[2],
                    latitude=row[3],
                    longitude=row[4]
                ))
            
            conn.close()
            return history
        except Exception as e:
            logging.error(f"Error getting location history: {str(e)}")
            return []

    def format_report(self, ip: str, data: Dict[str, Any]) -> str:
        report = [
            "=" * 60,
            f"IP ADDRESS ANALYSIS REPORT: {ip}",
            "=" * 60,
            "",
            "BASIC INFORMATION:",
            f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"IP Version: {ipaddress.ip_address(ip).version}",
            "",
            "OWNER INFORMATION:",
        ]

        if data.get('owner'):
            owner = data['owner']
            report.extend([
                f"Organisasi: {owner.organization}",
                f"Name: {owner.name or 'Not available'}",
                f"Email: {owner.email or 'Not available'}",
                f"Telephone: {owner.phone or 'Not available'}",
                f"Address: {owner.address or 'Not available'}",
                f"Created Date: {owner.created_date or 'Not available'}",
                f"Last Updated: {owner.updated_date or 'Not available'}"
            ])

        report.extend(["", "THREAT ANALYSIS:"])
        if data.get('threat'):
            threat = data['threat']
            report.extend([
                f"Status: {'SUSPICIOUS' if threat.is_malicious else 'SAFE'}",
                f"Trust Score: {threat.confidence_score}%",
                f"Number of Reports: {threat.recent_reports}",
                f"Category: {', '.join(threat.categories) if threat.categories else 'None'}",
                f"Last Reported: {threat.last_reported or 'Never'}"
            ])

        if data.get('device'):
            report.extend(["", "INFORMASI PERANGKAT:"])
            device = data['device']
            report.extend([
                f"Hostname: {device.hostname or 'Not available'}",
                f"Open port: {', '.join(map(str, device.ports)) if device.ports else 'None'}",
                f"Services: {', '.join(device.services) if device.services else 'Not detected'}",
                f"Operating system: {device.os or 'Not detectedi'}",
                f"Vulnerability: {', '.join(device.vulns) if device.vulns else 'Not found'}"
            ])

        if data.get('location_history'):
            report.extend(["", "HISTORY LOKASI:"])
            for loc in data['location_history'][:5]:  
                report.append(
                    f"{loc.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - "
                    f"{loc.city}, {loc.country} ({loc.latitude}, {loc.longitude})"
                )

        return "\n".join(report)

    async def analyze_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.validate_ip(ip):
            logging.error(f"Invalid IP address: {ip}")
            return None

        try:
            results = await asyncio.gather(
                self.get_whois_info(ip),
                self.check_threat_status(ip),
                self.get_device_info(ip)
            )

            data = {
                'owner': results[0],
                'threat': results[1],
                'device': results[2],
                'location_history': self.get_location_history(ip)
            }

            return data

        except Exception as e:
            logging.error(f"Error analyzing IP {ip}: {str(e)}")
            return None

    def save_report(self, ip: str, report: str) -> str:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = results_dir / f"ip_analysis_{ip}_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            return str(filename)
        except Exception as e:
            logging.error(f"Error saving report: {str(e)}")
            return ""

async def main():
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
    
    checker = SourceIpChecker()
    
    while True:
        print("\nMenu:")
        print("1. IP Address Analysis")
        print("2. View Analysis History")
        print("3. Exit")
        
        choice = input("\nYour choice (1-3): ").strip()
        
        if choice == "3":
            print("\nThank you for using Source IP Analyzer!")
            break
            
        elif choice == "1":
            ip = input("\nEnter the IP address: ").strip()
            
            print("\nAnalyze IP addresses...")
            data = await checker.analyze_ip(ip)
            
            if data:
                report = checker.format_report(ip, data)
                print(report)
                
                # save result
                saved_file = checker.save_report(ip, report)
                if saved_file:
                    print(f"\nThe analysis results are saved to: {saved_file}")
                else:
                    print("\nFailed to save analysis results")
            
        elif choice == "2":
            ip = input("\nEnter IP to view history: ").strip()
            history = checker.get_location_history(ip)
            
            if history:
                print(f"\nLocation history for IP {ip}:")
                for loc in history:
                    print(f"{loc.timestamp} - {loc.city}, {loc.country}")
            else:
                print("None history for that IP")
                
        else:
            print("\nInvalid choice! Please choose 1-3.")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
