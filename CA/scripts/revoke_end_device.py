#!/usr/bin/env python3
"""
@file create_end_device.py
@author COMSYS, RWTH Aachen University
@brief Script for registering new devices with the CA
@version 0.1
@date 2024-11-01

Certificate Revocation Script.

Provides functionality to revoke device certificates and update CA records.
Handles different revocation reasons and maintains revocation lists.
"""

import json
import argparse
import inspect
import json
import os
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

class RevocationReason(Enum):
    """
    Valid reasons for certificate revocation.
    
    Values:
        KEY_COMPROMISE: Device's private key has been compromised
        CA_COMPROMISE: CA's private key has been compromised
        CESSATION_OF_OPERATION: Device is no longer operational
        AFFILIATION_CHANGED: Device ownership/affiliation has changed
        UNSPECIFIED: Other unspecified reasons
    """
    KEY_COMPROMISE = "keyCompromise"
    CA_COMPROMISE = "CaCompromise"
    CESSATION_OF_OPERATION = "cessationOfOperation"
    AFFILIATION_CHANGED = "affiliationChanged"
    UNSPECIFIED = "unspecified"

class RevocationParser(object):
    """An arg parser for the end device registration."""

    def __init__(self):
        self.progname = "End Device Revocation"
        self.version = "0.1"
        self.programversion = "{0}{1}".format(self.progname, self.version)
        self.parser = argparse.ArgumentParser(
            description="Script that can revoke end devices at the CA."
        )

        self.identifier()
        self.revocationReason()

    def getParser(self):
        return self.parser

    def identifier(self):
        parser = self.parser
        parser.add_argument(
            "--identifier",
            metavar="IDENTIFIER",
            action="store",
            help="The identifier of the end device.",
        )

    def revocationReason(self):
        self.parser.add_argument(
            "--revocationReason",
            metavar="REVOCATIONREASON",
            choices=[reason.value for reason in RevocationReason],
            help="The reason for revocation: " + ", ".join(reason.value for reason in RevocationReason)
        )

def revoke_device(identifier: str, revocation_reason: str, base_path: Path) -> bool:
    """
    Revoke a device's certificate and update CA records.
    
    Args:
        identifier: Device's unique identifier
        revocation_reason: Reason for revocation from RevocationReason enum
        base_path: Base path to CA files
        
    Returns:
        bool: True if revocation successful, False otherwise
        
    Side effects:
        - Updates device's JSON file with revocation status
        - Removes public key from verification file
    """
    try:
        device_file = base_path / "Server/registered_end_devices" / f"{identifier}.json"
        with device_file.open("r+") as jsonfile:
            dictionary = json.load(jsonfile)
            dictionary["certificate status"] = "revoked"
            dictionary["revocation reason"] = revocation_reason
            jsonfile.seek(0)
            jsonfile.truncate()
            json.dump(dictionary, jsonfile, indent=4)

        # Remove key from verification file
        pubkey_file = base_path / "Server/certification_materials/public_keys.txt"
        key = dictionary["public_key"].strip()
        
        with pubkey_file.open("r") as f:
            lines = [line for line in f if key not in line]
        
        with pubkey_file.open("w") as f:
            f.writelines(lines)
            
        return True
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
        print(f"Error revoking device: {e}")
        return False

def main():
    argparser = RevocationParser()
    args = argparser.getParser().parse_args()
    
    if not args.identifier:
        print("Please provide an identifier")
        return 1
        
    if not args.revocationReason:
        print("Please provide a revocation reason")
        return 1
        
    base_path = Path(__file__).parent.parent
    
    if revoke_device(args.identifier, args.revocationReason, base_path):
        print(f"Successfully revoked device {args.identifier}")
        return 0
    else:
        print("Failed to revoke device")
        return 1

if __name__ == "__main__":
    sys.exit(main())
