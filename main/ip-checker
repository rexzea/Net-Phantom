import requests
import re
import json
from typing import Optional, Dict, Union

class IPChecker:
    def __init__(self):
        self.base_url = "http://ip-api.com/json/"
    
    def is_valid_ip(self, ip: str) -> bool:
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))
    
    def get_ip_info(self, ip: str) -> Optional[Dict[str, Union[str, float]]]:
        try:
            response = requests.get(f"{self.base_url}{ip}")
            response.raise_for_status()  # status error code
            data = response.json()
            
            if data.get("status") == "fail":
                print(f"\nError: {data.get('message', 'Unknown error')}")
                return None
                
            return {
                'IP': ip,
                'city': data.get('city', 'Not available'),
                'Region': data.get('regionName', 'Not available'),
                'country': data.get('country', 'Not available'),
                'Postal code': data.get('zip', 'Not available'),
                'ISP': data.get('isp', 'Not available'),
                'Latitude': data.get('lat', 'Not available'),
                'Longitude': data.get('lon', 'Not available')
            }
            
        except requests.exceptions.RequestException as e:
            print(f"\nError network: {str(e)}")
            return None
        except json.JSONDecodeError:
            print("\nError: Failed to process the response from the server")
            return None
        except Exception as e:
            print(f"\nError Unexpected: {str(e)}")
            return None

def main():
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
    
    checker = IPChecker()
    
    while True:
        print("\nPlease select an option:")
        print("1. Check IP address")
        print("2. Exit")
        
        choice = input("\nYour choice (1/2): ").strip()
        
        if choice == "2":
            print("\nThank you for using IP Checker!")
            break
        elif choice == "1":
            ip = input("\nEnter the IP address (example: 8.8.8.8): ").strip()
            
            if not checker.is_valid_ip(ip):
                print("\nError: Invalid IP address format!")
                continue
            
            print("\nRetrieving information...")
            ip_info = checker.get_ip_info(ip)
            
            if ip_info:
                print("\n=== IP Address Information ===")
                for key, value in ip_info.items():
                    print(f"{key}: {value}")
        else:
            print("\nInvalid choice! Please choose 1 or 2!")

if __name__ == "__main__":
    main()