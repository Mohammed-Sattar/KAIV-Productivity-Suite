#!/usr/bin/env python3

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, urlunparse, ParseResult
from socketserver import ThreadingMixIn
from http.client import HTTPResponse
from tempfile import gettempdir
from os import path, listdir
import ssl
from socket import socket
from re import compile
from sys import argv
from datetime import datetime, timedelta
import subprocess
import sys
import os
import threading
import socketserver
import struct
import dns.message
import dns.query

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PyMiProxy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

__all__ = [
    'CertificateAuthority',
    'ProxyHandler',
    'RequestInterceptorPlugin',
    'ResponseInterceptorPlugin',
    'MitmProxy',
    'AsyncMitmProxy',
    'InvalidInterceptorPluginException'
]


class CertificateAuthority(object):

    def __init__(self, ca_file='ca.pem', cache_dir=gettempdir()):
        self.ca_file = ca_file
        self.cache_dir = cache_dir
        self._serial = self._get_serial()
        if not path.exists(ca_file):
            self._generate_ca()
        else:
            self._read_ca(ca_file)

    def _get_serial(self):
        s = 1
        for c in filter(lambda x: x.startswith('.pymp_'), listdir(self.cache_dir)):
            with open(path.sep.join([self.cache_dir, c]), 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                sc = cert.serial_number
                if sc > s:
                    s = sc
        return s

    def _generate_ca(self):
        # Generate key
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'ca.mitm.com'),
        ])

        self.cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
            critical=False
        ).sign(self.key, hashes.SHA256(), default_backend())

        # Write to disk
        with open(self.ca_file, 'wb+') as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))

    def _read_ca(self, file):
        with open(file, 'rb') as f:
            data = f.read()
            self.key = serialization.load_pem_private_key(
                data,
                password=None,
                backend=default_backend()
            )
            self.cert = x509.load_pem_x509_certificate(data, default_backend())

    def __getitem__(self, cn):
        cnp = path.sep.join([self.cache_dir, '.pymp_%s.pem' % cn])
        if not path.exists(cnp):
            # Generate key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            # Generate CSR
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                self.cert.subject
            ).public_key(
                key.public_key()
            ).serial_number(
                self._serial
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(cn)]),
                critical=False,
            ).sign(self.key, hashes.SHA256(), default_backend())

            self._serial += 1

            # Save the key and certificate
            with open(cnp, 'wb+') as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                f.write(cert.public_bytes(serialization.Encoding.PEM))

        return cnp


class UnsupportedSchemeException(Exception):
    pass


class ProxyHandler(BaseHTTPRequestHandler):

    r = compile(r'(?i)http://[^/]+(?:/.*)?')

    def __init__(self, request, client_address, server):
        self.is_connect = False
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _connect_to_host(self):
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            u = urlparse(self.path)
            if u.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s' % repr(u.scheme))
            self.hostname = u.hostname
            self.port = u.port or 80

        # Connect to destination
        self._proxy_sock = socket()
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self._proxy_sock = context.wrap_socket(self._proxy_sock, server_hostname=self.hostname)

    def _transition_to_ssl(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.server.ca[self.path.split(':')[0]])
        self.request = context.wrap_socket(self.request, server_side=True)


    def do_CONNECT(self):
        self.is_connect = True
        try:
            # Connect to destination first
            self._connect_to_host()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            #self.request.sendall('%s 200 Connection established\r\n\r\n' % self.request_version)
            self._transition_to_ssl()
        except Exception as e:
            self.send_error(500, str(e))
            return

        # Reload!
        self.setup()
        self.ssl_host = 'https://%s' % self.path
        self.handle_one_request()


    def do_COMMAND(self):

        # Is this an SSL tunnel?
        if not self.is_connect:
            try:
                # Connect to destination
                self._connect_to_host()
            except Exception as e:
                self.send_error(500, str(e))
                return
            # Extract path

        # Build request
        req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)

        # Add headers to the request
        req += '%s\r\n' % self.headers

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        # Send it down the pipe!
        self._proxy_sock.sendall(self.mitm_request(req))

        # Parse response
        h = HTTPResponse(self._proxy_sock)
        h.begin()

        # Get rid of the pesky header
        del h.msg['Transfer-Encoding']

        # Time to relay the message across
        res = '%s %s %s\r\n' % (self.request_version, h.status, h.reason)
        res += '%s\r\n' % h.msg
        res += h.read()

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        # Relay the message
        self.request.sendall(self.mitm_response(res))

    def mitm_request(self, data):
        for p in self.server._req_plugins:
            data = p(self.server, self).do_request(data)
        return data

    def mitm_response(self, data):
        for p in self.server._res_plugins:
            data = p(self.server, self).do_response(data)
        return data

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND

    def log_message(self, format, *args):
        # Override to provide more detailed logging
        message = format % args
        print(f"\n[INFO] {self.client_address[0]}:{self.client_address[1]} - {message}")


class InterceptorPlugin(object):

    def __init__(self, server, msg):
        self.server = server
        self.message = msg


class RequestInterceptorPlugin(InterceptorPlugin):

    def do_request(self, data):
        return data


class ResponseInterceptorPlugin(InterceptorPlugin):

    def do_response(self, data):
        return data


class InvalidInterceptorPluginException(Exception):
    pass


class MitmProxy(HTTPServer):

    def __init__(self, server_address=('', 8080), RequestHandlerClass=ProxyHandler, bind_and_activate=True, ca_file='ca.pem'):
        HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.ca = CertificateAuthority(ca_file)
        self._res_plugins = []
        self._req_plugins = []

    def register_interceptor(self, interceptor_class):
        if not issubclass(interceptor_class, InterceptorPlugin):
            raise InvalidInterceptorPluginException('Expected type InterceptorPlugin got %s instead' % type(interceptor_class))
        if issubclass(interceptor_class, RequestInterceptorPlugin):
            self._req_plugins.append(interceptor_class)
        if issubclass(interceptor_class, ResponseInterceptorPlugin):
            self._res_plugins.append(interceptor_class)


class AsyncMitmProxy(ThreadingMixIn, MitmProxy):
    pass


class MitmProxyHandler(ProxyHandler):

    def mitm_request(self, data):
        print('>> %s' % repr(data[:100]))
        return data

    def mitm_response(self, data):
        print('<< %s' % repr(data[:100]))
        return data


class DebugInterceptor(RequestInterceptorPlugin, ResponseInterceptorPlugin):
    def do_request(self, data):
        try:
            print('\n[-->] Outgoing Request:')
            print('-' * 50)
            decoded_data = data.decode('utf-8', errors='ignore')
            print(f"Length: {len(data)} bytes")
            print(decoded_data[:500])  # Show more data
            print('-' * 50)
        except Exception as e:
            print(f"Error decoding request: {e}")
        return data

    def do_response(self, data):
        try:
            print('\n[<--] Incoming Response:')
            print('-' * 50)
            decoded_data = data.decode('utf-8', errors='ignore')
            print(f"Length: {len(data)} bytes")
            print(decoded_data[:500])  # Show more data
            print('-' * 50)
        except Exception as e:
            print(f"Error decoding response: {e}")
        return data


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        
        try:
            # Parse the DNS query
            query = dns.message.from_wire(data)
            print(f"\n[DNS Query] {query.question[0].name}")
            
            # Forward the query to the real DNS server (e.g., 8.8.8.8)
            response = dns.query.udp(query, "8.8.8.8")
            
            # Send the response back to the client
            socket.sendto(response.to_wire(), self.client_address)
            print(f"[DNS Response] Resolved to: {[str(rr) for rr in response.answer]}")
            
        except Exception as e:
            print(f"[DNS Error] {e}")


class ThreadedDNSServer(socketserver.ThreadingUDPServer):
    def __init__(self, server_address):
        super().__init__(server_address, DNSHandler)


def verify_environment():
    # When running with sudo, we're already using the correct Python interpreter
    # so we don't need to check the environment variables
    if os.geteuid() == 0:  # If running as root/sudo
        return
        
    # These checks only apply when not running as root
    if 'CONDA_DEFAULT_ENV' not in os.environ:
        print("Error: This script must be run in a conda environment")
        sys.exit(1)
    
    if os.environ.get('CONDA_DEFAULT_ENV') != 'MITM_Proxy':
        print("Error: Wrong conda environment")
        print(f"Current environment: {os.environ.get('CONDA_DEFAULT_ENV')}")
        print("Please activate the correct environment with:")
        print("    conda activate MITM_Proxy")
        sys.exit(1)
    
    # Get the conda environment's Python path
    conda_prefix = os.environ.get('CONDA_PREFIX')
    if not conda_prefix:
        print("Error: Could not determine conda environment path")
        sys.exit(1)
    
    # Store the Python path for sudo usage
    global CONDA_PYTHON_PATH
    CONDA_PYTHON_PATH = os.path.join(conda_prefix, 'bin', 'python')

def setup_transparent_proxy():
    if os.geteuid() != 0:
        print("Error: This script must be run as root to set up transparent proxying")
        print(f"Please run with: sudo {CONDA_PYTHON_PATH} {__file__}")
        sys.exit(1)
    
    try:
        print("\nSetting up transparent proxy rules...")
        
        # Flush existing rules
        print("- Flushing existing NAT rules...")
        subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
        
        # Redirect HTTP traffic (port 80)
        print("- Setting up HTTP (port 80) redirection...")
        subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", "tcp", "--dport", "80",
            "-j", "REDIRECT", "--to-port", "8080"
        ], check=True)
        
        # Redirect HTTPS traffic (port 443)
        print("- Setting up HTTPS (port 443) redirection...")
        subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", "tcp", "--dport", "443",
            "-j", "REDIRECT", "--to-port", "8080"
        ], check=True)

        # Redirect DNS traffic (port 53)
        print("- Setting up DNS (port 53) redirection...")
        subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", "udp", "--dport", "53",
            "-j", "REDIRECT", "--to-port", "5353"
        ], check=True)
        subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", "tcp", "--dport", "53",
            "-j", "REDIRECT", "--to-port", "5353"
        ], check=True)

        # Verify rules are in place
        print("\nVerifying iptables rules:")
        subprocess.run(["iptables", "-t", "nat", "-L", "PREROUTING", "--line-numbers"], check=True)
        
        print("\nTransparent proxy setup completed successfully")
        print("Note: DNS redirection is enabled on port 5353")
    except subprocess.CalledProcessError as e:
        print(f"\nError setting up transparent proxy: {e}")
        sys.exit(1)

def cleanup_transparent_proxy():
    try:
        print("\nCleaning up transparent proxy rules...")
        subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
        print("Cleaned up transparent proxy rules successfully")
    except subprocess.CalledProcessError as e:
        print(f"\nError cleaning up transparent proxy: {e}")


if __name__ == '__main__':
    verify_environment()
    proxy = None
    if not argv[1:]:
        proxy = AsyncMitmProxy()
    else:
        proxy = AsyncMitmProxy(ca_file=argv[1])

    print("\nProxy server starting...")
    print("Setting up transparent proxying...")
    setup_transparent_proxy()
    
    # Start DNS server in a separate thread
    dns_server = ThreadedDNSServer(('localhost', 5353))
    dns_thread = threading.Thread(target=dns_server.serve_forever)
    dns_thread.daemon = True
    dns_thread.start()
    
    print("Listening on: localhost:8080 (HTTP/HTTPS)")
    print("DNS Interception: localhost:5353")
    print("All HTTP/HTTPS and DNS traffic will be automatically intercepted")
    print("Press Ctrl+C to exit\n")
    
    proxy.register_interceptor(DebugInterceptor)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        print("\nCleaning up...")
        cleanup_transparent_proxy()
        dns_server.shutdown()
        dns_server.server_close()
        proxy.server_close()
