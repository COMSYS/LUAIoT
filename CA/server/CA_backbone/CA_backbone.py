#!/usr/bin/env python3
"""
@file CA_backbone.py
@author COMSYS, RWTH Aachen University
@brief Script for registering new devices with the CA
@version 0.1
@date 2024-11-01

Certificate Authority Core Implementation.

Implements core functionality for certificate generation, signing, and management
operations. Handles enrollment requests and certificate issuance.
"""

import inspect
import os
import sys
import json
import datetime
import struct
from typing import Optional, Tuple

from enum import Enum
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

import base64

from OpenSSL import crypto

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)


"""
Certificate Authority Core Implementation
Handles certificate generation, signing, and management operations.
"""

# return codes for the different check
class ReturnCodes(Enum):
    """
    Return codes for certificate operations.
    
    Values:
        malformedRequest: Request format is invalid
        malformedIdentifier: Device identifier is invalid
        identifierOnRevocationList: Device has been revoked
        accountDoesNotExist: No registration found for device
        malformedPublicKey: Invalid public key format
        serverInternal: Internal server error
    """
    malformedRequest = 0
    malformedIdentifier = 1
    identifierOnRevocationList = 2
    accountDoesNotExist = 3
    malformedPublicKey = 4
    serverInternal = 5


# an object of this class performs the enrollment request check and creates the certificates
class CertificateAuthorityBackbone(object):
    """
    Core CA functionality for certificate management.
    Handles enrollment requests, certificate generation and signing.
    
    Args:
        issuer_name: Name of the certificate issuer (default: "acaiot")
    """
    def __init__(self, issuer_name: str = "acaiot"):
        self.__issuer_name = issuer_name
        self.__load_ca_credentials()
        self.__setup_ocsp()

    def __load_ca_credentials(self):
        """Load CA private key and certificate"""
        with open("certification_materials/ca-key.pem", "rb") as key_file:
            self.__private_key = serialization.load_pem_private_key(key_file.read(), None)
        
        with open("certification_materials/ca-cert.pem") as cert_file:
            self.__own_certificate = cert_file.read()

    def __setup_ocsp(self):
        """Configure OCSP responder"""
        self.__ocsp_responder = x509.AccessDescription(
            access_method=AuthorityInformationAccessOID.OCSP,
            access_location=x509.DNSName("localhost"),
        )

    def checkEnrollmentRequest(self, identifier: str, publicKey: str):
        """Check the request of the devices."""

        print()
        print("CSR:")
        print(publicKey)
        print()

        # unpack the struct
        try:
            requestStruct = struct.unpack("37s c c c", identifier)
        except:
            print("Malformed Request")
            return ReturnCodes.malformedRequest

        # check if email is set to Y
        if requestStruct[1] != b"Y":
            print("Email bit wrong")
            return ReturnCodes.malformedRequest

        # get the identifier and check it
        identifier = requestStruct[0]
        identifier = identifier.decode("ascii")
        if identifier[20] != ":" or identifier[31] != ":":
            print("Malformed identifier")
            return ReturnCodes.malformedIdentifier

        # get telephone and address values
        telephone = False
        address = False
        if requestStruct[2].decode("ascii") == "Y":
            telephone = True
        if requestStruct[3].decode("ascii") == "Y\0":
            address = True

        # issue the certificate
        returnCode = self.issue_Certificate(identifier, publicKey, telephone, address)
        return returnCode

    def generate_certificate(self, csr_bytes: bytes) -> x509.Certificate:
        """Generate a new certificate from CSR"""
        csr = x509.load_der_x509_csr(base64.b64decode(csr_bytes))
        
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.__issuer_name)
        ]))
        
        validity = datetime.timedelta(days=30)
        now = datetime.datetime.today()
        
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now - datetime.timedelta(days=1))
        builder = builder.not_valid_after(now + validity)
        
        cert = builder.sign(
            private_key=self.__private_key,
            algorithm=hashes.SHA256()
        )
        
        return cert

    def embed_certificate_into_pkcs7(self, certificate):
        pkcs7_data = pkcs7.serialize_certificates([certificate], Encoding.DER)
        return pkcs7_data


    def issue_Certificate(
        self, identifier: str, publicKey, telephone: bool, address: bool
    ):
        """Create the certificate and peforms checks on the provided information."""
        # get the public key of the end device
        try:
            with open(
                "{}{}.json".format(self.__registeredDevicesFolder, identifier), "r"
            ) as jsonfile:
                dictionary = json.load(jsonfile)

                # check revocation status
                if dictionary["certificate status"] == "revoked":
                    print("revoked certificate")
                    return ReturnCodes.identifierOnRevocationList

                # create public key object
                try:
                    public_key_device = load_pem_public_key(publicKey)
                except:
                    print("Malformed public key")
                    return ReturnCodes.malformedPublicKey
                # check if there is an alternative identifier present
                if dictionary["alternative identifier"] != None:
                    newIdentifier = dictionary["alternative identifier"]
                else:
                    newIdentifier = identifier

        except:
            print("Could not find json file for identifier")
            return ReturnCodes.accountDoesNotExist

        if dictionary["telephone"] == "" or dictionary["telephone"] == None:
            telephone = False
        if dictionary["address"]["country"] == "" or dictionary["address"]["country"] == None:
            address = False

        # build the certificate
        one_day = datetime.timedelta(1, 0, 0)
        builder = x509.CertificateBuilder()

        # add email, telephone, and postal address into certificate
        if telephone and address:
            builder = builder.subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, newIdentifier),
                        x509.NameAttribute(NameOID.EMAIL_ADDRESS, dictionary["email"]),
                        x509.NameAttribute(
                            NameOID.UNSTRUCTURED_NAME, dictionary["telephone"]
                        ),
                        x509.NameAttribute(
                            NameOID.COUNTRY_NAME, dictionary["address"]["country"]
                        ),
                        x509.NameAttribute(
                            NameOID.STATE_OR_PROVINCE_NAME,
                            dictionary["address"]["state"],
                        ),
                        x509.NameAttribute(
                            NameOID.LOCALITY_NAME, dictionary["address"]["city"]
                        ),
                    ]
                )
            )
        # add telephone, and email address into certificate
        elif telephone:
            builder = builder.subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, identifier),
                        x509.NameAttribute(NameOID.EMAIL_ADDRESS, dictionary["email"]),
                        x509.NameAttribute(
                            NameOID.UNSTRUCTURED_NAME, dictionary["telephone"]
                        ),
                    ]
                )
            )
        # add email, and postal address into certificate
        elif address:
            builder = builder.subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, identifier),
                        x509.NameAttribute(NameOID.EMAIL_ADDRESS, dictionary["email"]),
                        x509.NameAttribute(NameOID.COUNTRY_NAME, dictionary["country"]),
                        x509.NameAttribute(
                            NameOID.STATE_OR_PROVINCE_NAME, dictionary["state"]
                        ),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, dictionary["city"]),
                    ]
                )
            )
        # add email into certificate
        else:
            builder = builder.subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, identifier),
                        x509.NameAttribute(NameOID.EMAIL_ADDRESS, dictionary["email"]),
                    ]
                )
            )

        # add the remaining parts of the certificate
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, self.__issuerName),
                ]
            )
        )
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + 30 * one_day)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key_device)
        builder = builder.add_extension(
            x509.SubjectInformationAccess([self.__ocspResponder]), critical=True
        )

        # sign the certifictae
        certificate = builder.sign(
            private_key=self.__private_key, algorithm=hashes.SHA256()
        )
        # serialize certificate
        certificateSerialized = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode("ascii")

        # change status of device registration
        with open(
            "{}{}.json".format(self.__registeredDevicesFolder, identifier), "w"
        ) as jsonfile:
            if dictionary["certificate status"] == "registered":
                dictionary["certificate status"] = "certified"
            dictionary["certificate"] = certificateSerialized
            jsonfile.write(json.dumps(dictionary, indent=4))

        # return the certificate
        return certificateSerialized

    def handle_enrollment_request(self, request: str) -> str:
        """Handle enrollment request and return PKCS7 response"""
        csr = self.__extract_csr(request)
        cert = self.generate_certificate(csr.encode('utf-8'))
        pkcs7_der = self.embed_certificate_into_pkcs7(cert)
        response = self.__format_response(pkcs7_der)
        return response

    def __extract_csr(self, request: str) -> str:
        """Extract CSR from request"""
        return "".join(request.split("\r\n")[3::])

    def __format_response(self, pkcs7_der: bytes) -> str:
        """Format HTTP response with PKCS7 certificate"""
        pkcs7_b64 = base64.b64encode(pkcs7_der).decode('utf-8')
        return (
            f"HTTP/1.0 200 OK\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(pkcs7_b64)}\r\n\r\n"
            f"{pkcs7_b64}"
        )
