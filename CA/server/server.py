#!/usr/bin/env python3
"""
@file server.py
@author COMSYS, RWTH Aachen University
@brief Script for registering new devices with the CA
@version 0.1
@date 2024-11-01

Certificate Authority Server Implementation.

This module implements the core server functionality for the Certificate Authority,
handling TLS connections and certificate management.
"""

import sys
import signal
import os
import socket
import json
import time
import logging
from typing import Dict, List
from pathlib import Path

# necessary imports for gnutls
from threading import Thread
from gnutls.crypto import *
from gnutls.connection import *
from gnutls.library.types import gnutls_session_t, gnutls_certificate_verify_function
from gnutls.library.functions import gnutls_verify_stored_pubkey, gnutls_certificate_get_peers
from gnutls.library.constants import GNUTLS_E_CERTIFICATE_ERROR, GNUTLS_CRT_RAWPK

from ctypes import (
    c_uint,
    byref
)

# imports for the CA and the evaluation
from CA_backbone.CA_backbone import CertificateAuthorityBackbone

# Add logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

ca_backbone = CertificateAuthorityBackbone()

# function that verifies the RPK of the clients
@gnutls_certificate_verify_function
def _verify_rawPK_callback(session: gnutls_session_t):
    """
    Verify the Raw Public Key (RPK) of connecting clients.
    
    Args:
        session: The GnuTLS session containing client certificate
    Returns:
        int: 0 on success, error code on failure
    """
    try:
        list_size = c_uint()
        cert_list = gnutls_certificate_get_peers(session, byref(list_size))
        if not cert_list or list_size.value == 0:
            print("No certificate was found!\n")
            return GNUTLS_E_CERTIFICATE_ERROR
            
        return gnutls_verify_stored_pubkey(
            b"certification_materials/public_keys.txt",
            None,
            b"host",
            None,
            GNUTLS_CRT_RAWPK,
            cert_list[0],
            0
        )
    except Exception as e:
        print(f"Verification of certificate failed: {e}")
        return GNUTLS_E_CERTIFICATE_ERROR

# class that handles the TLS connection
class SessionHandler(Thread):
    """
    Handles individual TLS sessions with clients.
    Processes certificate requests and measurements for evaluation.
    """
    def __init__(self, session, address, ca_backbone, metrics):
        Thread.__init__(self, name="SessionHandler")
        self.daemon = True
        self.session = session
        self.address = address
        self.ca_backbone = ca_backbone
        self.metrics = metrics

    def run(self):
        """Listen for incoming data and work on the data"""
        session = self.session
        # perform the TLS handshake
        try:
            session.handshake()
        except Exception as e:
            logging.error("Handshake failed with client %s:%d - %s", 
                         self.address[0], self.address[1], str(e))
        else:
            while True:
                try:
                    # receive data
                    buf = session.recv(4000)
                    # check for error
                    if not buf:
                        logging.info("Client %s:%d closed the session", 
                                   self.address[0], self.address[1])
                        break

                    # create the certificate
                    response = self.ca_backbone.handle_enrollment_request(buf.decode())
                    session.send(response.encode("ascii"))
                except Exception as e:
                    logging.error("Error processing request from %s:%d - %s", 
                                self.address[0], self.address[1], str(e))
                    break

        try:
            session.shutdown()
        except Exception as e:
            logging.warning("Error during session shutdown for %s:%d - %s", 
                          self.address[0], self.address[1], str(e))
        session.close()


class CAServer:
    """
    Certificate Authority Server main class.
    Manages TLS connections, certificate operations and metrics collection.
    
    Args:
        host: Server host address
        port: Server port number
    """
    def __init__(self, host: str = "0.0.0.0", port: int = 5556):
        self.host = host
        self.port = port
        self.ca_backbone = CertificateAuthorityBackbone()
        self.setup_tls()
        self.setup_metrics()

    def setup_tls(self):
        """Setup TLS context and credentials"""
        certs_path = Path("certification_materials")
        
        creds = X509Credentials(
            [X509Certificate(open(certs_path / "server-cert.pem").read()),
             X509Certificate(open(certs_path / "inter-cert.pem").read())],
             X509PrivateKey(open(certs_path / "server-key.pem").read()),
            [X509Certificate(open(certs_path / "ca-cert.pem").read())],
            []
        )
        
        creds.set_verify_function(_verify_rawPK_callback)
        self.context = TLSContext(creds, session_parameters="PERFORMANCE:+CTYPE-CLI-RAWPK")

    def setup_metrics(self):
        """Initialize metrics collection"""
        self.metrics = {name: {} for name in [
            "HandleCertification",
            "KeyCreation", 
            "CreatingEnrollmentRequest",
            "LatencyBetweenRequestResponse",
            "HandleEnrollmentResponse",
            "CA_Create_Certificate"
        ]}

    def run(self):
        """Run the server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            factory = ServerSessionFactory(sock, self.context)
            factory.bind((self.host, self.port))
            factory.listen(10)

            logging.info("Server started successfully on %s:%d", self.host, self.port)
            
            while True:
                try:
                    session, address = factory.accept()
                    logging.info("New connection from %s:%d", address[0], address[1])
                    SessionHandler(session, address, self.ca_backbone, self.metrics).start()
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    logging.error("Error accepting connection: %s", str(e))
        except Exception as e:
            logging.critical("Failed to start server: %s", str(e))
            raise


def shutdown(sig, frame):
    """Shutdown the server and evaluate the received measurements"""
    logging.info("Shutdown signal %s received. Initiating server shutdown...", sig)
    # Perform any necessary cleanup tasks here
    logging.info("Server shutdown complete")
    sys.exit(0)


if __name__ == "__main__":
    # for shutting down
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # run the server
    server = CAServer()
    server.run()
