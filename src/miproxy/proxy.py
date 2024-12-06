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
            print('>> %s' % repr(data[:100]))
            return data

        def do_response(self, data):
            print('<< %s' % repr(data[:100]))
            return data


def verify_environment():
    # Check if running in conda environment
    if 'CONDA_DEFAULT_ENV' not in os.environ:
        print("Error: This script must be run in a conda environment")
        sys.exit(1)
    
    # Check if it's the correct environment
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
        # Flush existing rules
        subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
        
        # Redirect HTTP traffic (port 80)
        subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", "tcp", "--dport", "80",
            "-j", "REDIRECT", "--to-port", "8080"
        ], check=True)
        
        # Redirect HTTPS traffic (port 443)
        subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", "tcp", "--dport", "443",
            "-j", "REDIRECT", "--to-port", "8080"
        ], check=True)
        
        print("Successfully set up transparent proxying")
    except subprocess.CalledProcessError as e:
        print(f"Error setting up transparent proxy: {e}")
        sys.exit(1)

def cleanup_transparent_proxy():
    try:
        # Remove the iptables rules
        subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
        print("Cleaned up transparent proxy rules")
    except subprocess.CalledProcessError as e:
        print(f"Error cleaning up transparent proxy: {e}")


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
    print("Listening on: localhost:8080")
    print("All HTTP/HTTPS traffic will be automatically intercepted")
    print("Press Ctrl+C to exit\n")
    
    proxy.register_interceptor(DebugInterceptor)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        print("\nCleaning up...")
        cleanup_transparent_proxy()
        proxy.server_close()
