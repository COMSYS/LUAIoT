#!/usr/bin/env python3
"""
@file create_end_device_entry.py
@author COMSYS, RWTH Aachen University
@brief Script for registering new devices with the CA
@version 0.1
@date 2024-11-01

Handles the registration of new devices with the Certificate Authority.
Validates device information and creates necessary registration records.
"""

import json
import argparse
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Optional
import re

currentdir = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)


class RegistrationParser(object):
    """An arg parser for the end device registration."""

    def __init__(self):
        self.progname = "End Device Registration"
        self.version = "0.1"
        self.programversion = "{0}{1}".format(self.progname, self.version)
        self.parser = argparse.ArgumentParser(
            description="Script that can register end devices at the CA.")

        self.identifier()
        self.publicKey()
        self.user()
        self.email()
        self.telephone()
        self.country()
        self.state()
        self.city()

    def getParser(self):
        return self.parser

    def identifier(self):
        parser = self.parser
        parser.add_argument("--identifier", metavar="IDENTIFIER",
                            action="store", help="The identifier of the end device.")
        
    def publicKey(self):
        parser = self.parser
        parser.add_argument("--publicKey", metavar="PUBLICKEY",
                            action="store", help="The path to the public key of the end device.")
        
    def user(self):
        parser = self.parser
        parser.add_argument("--user", metavar="USER",
                            action="store", help="The user that registered the end device.")
        
    def email(self):
        parser = self.parser
        parser.add_argument("--email", metavar="EMAIL",
                            action="store", help="The email of the user that registered the end device.")
        
    def telephone(self):
        parser = self.parser
        parser.add_argument("--telephone", metavar="TELEPHONE",
                            action="store", help="The telephone number of the user that registered the end device.")

    def country(self):
        parser = self.parser
        parser.add_argument("--country", metavar="COUNTRY",
                            action="store", help="The country the user lives in.")
        
    def state(self):
        parser = self.parser
        parser.add_argument("--state", metavar="STATE",
                            action="store", help="The state the user lives in.")
        
    def city(self):
        parser = self.parser
        parser.add_argument("--city", metavar="CITY",
                            action="store", help="The city the user lives in.")

"""
Device Registration Script
Handles the registration of new devices with the Certificate Authority.
Validates device information and creates necessary records.
"""

class DeviceRegistration:
    """
    Handles device registration operations.
    Validates device information and manages registration records.
    
    Properties:
        IDENTIFIER_PATTERN: Regex pattern for valid device identifiers
    
    Args:
        base_path: Root path to CA installation
    """
    IDENTIFIER_PATTERN = re.compile(r'^.{20}:.{10}:.{5}$')
    
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.public_keys_dir = base_path / "scripts/public_keys"
        self.devices_dir = base_path / "Server/registered_end_devices"
        self.cert_materials = base_path / "Server/certification_materials"
        
    def validate_identifier(self, identifier: str, user: str) -> bool:
        """
        Validate device identifier format and user association.
        
        Args:
            identifier: Device's unique identifier
            user: Associated username
            
        Returns:
            bool: True if identifier is valid, False otherwise
            
        Format requirements:
            - Must match IDENTIFIER_PATTERN regex
            - User portion must match provided username
        """
        if not self.IDENTIFIER_PATTERN.match(identifier):
            print("Invalid identifier format")
            return False
        if identifier[21:31] != user:
            print("User mismatch in identifier")
            return False
        return True
        
    def read_public_key(self, key_file: str) -> Optional[str]:
        try:
            key_path = self.public_keys_dir / key_file
            content = key_path.read_text().splitlines()
            return "".join(content[1:-1])
        except (FileNotFoundError, IndexError) as e:
            print(f"Error reading public key: {e}")
            return None
            
    def register_device(self, data: dict) -> bool:
        try:
            device_file = self.devices_dir / f"{data['identifier']}.json"
            device_file.write_text(json.dumps(data, indent=4))
            
            # Update verification file
            key_check = f"|g0|host|*|0|{data['public_key']}"
            verify_file = self.cert_materials / "public_keys.txt"
            with verify_file.open("a") as f:
                f.write(f"{key_check.strip()}\n")
                
            return True
        except Exception as e:
            print(f"Error registering device: {e}")
            return False

def main():
    argparser = RegistrationParser()
    args = argparser.getParser().parse_args()
    
    if not all([args.identifier, args.publicKey, args.user, args.email]):
        print("Missing required arguments")
        return 1
        
    registration = DeviceRegistration(Path(__file__).parent.parent)
    
    if not registration.validate_identifier(args.identifier, args.user):
        return 1
        
    public_key = registration.read_public_key(args.publicKey)
    if not public_key:
        return 1
        
    device_data = {
        "identifier": args.identifier,
        "public_key": public_key,
        "user": args.user,
        "email": args.email,
        "telephone": args.telephone,
        "address": {
            "country": args.country,
            "state": args.state,
            "city": args.city
        },
        "certificate status": "registered"
    }
    
    if registration.register_device(device_data):
        print(f"Successfully registered device {args.identifier}")
        return 0
    else:
        print("Failed to register device")
        return 1

if __name__ == "__main__":
    sys.exit(main())
