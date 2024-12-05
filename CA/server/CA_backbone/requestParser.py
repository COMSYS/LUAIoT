#!/usr/bin/env python3
"""
@file requestParser.py
@author COMSYS, RWTH Aachen University
@brief Script for registering new devices with the CA
@version 0.1
@date 2024-11-01

HTTP Request Parser for Certificate Authority.

Provides functionality to parse and validate HTTP requests, with support for
headers and body content processing.
"""

from dataclasses import dataclass
from typing import Dict

@dataclass
class HTTPRequest:
    """
    Data structure representing a parsed HTTP request.
    
    Attributes:
        method: HTTP method (GET, POST, etc.)
        url: Request URL
        protocol: HTTP protocol version
        headers: Dictionary of request headers
        body: Request body content
    """
    method: str
    url: str
    protocol: str
    headers: Dict[str, str]
    body: str

class RequestParser:
    """
    Parser for HTTP requests with support for headers and body content.
    Handles protocol version defaults and proper line splitting.
    """
    DEFAULT_HTTP_VERSION = "HTTP/1.0"
    NEWLINE = "\r\n"

    @classmethod
    def parse(cls, request_text: str) -> HTTPRequest:
        """Parse HTTP request text into HTTPRequest object"""
        lines = request_text.split(cls.NEWLINE)
        method, url, protocol = cls.__parse_request_line(lines[0])
        headers = cls.__parse_headers(lines[1:])
        body = cls.__parse_body(lines)
        
        return HTTPRequest(
            method=method,
            url=url,
            protocol=protocol,
            headers=headers,
            body=body
        )

    @classmethod
    def __parse_request_line(cls, line: str) -> tuple[str, str, str]:
        """Parse the first line of HTTP request"""
        parts = line.split(" ")
        return (
            parts[0],
            parts[1],
            parts[2] if len(parts) > 2 else cls.DEFAULT_HTTP_VERSION
        )

    @classmethod
    def __parse_headers(cls, lines: list[str]) -> Dict[str, str]:
        """Parse HTTP headers"""
        headers = {}
        for line in lines:
            if not line:
                break
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        return headers

    @classmethod
    def __parse_body(cls, lines: list[str]) -> str:
        """Parse HTTP body"""
        try:
            body_start = lines.index("") + 1
            return cls.NEWLINE.join(lines[body_start:])
        except ValueError:
            return ""
