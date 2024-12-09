from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer
import socket
import re
import logging
import platform
import os
import sys
import subprocess
import time
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)

class DNSConfigurator:
    def __init__(self):
        self.system = platform.system().lower()
        self.original_dns = self._get_current_dns()

    def _get_current_dns(self) -> Optional[str]:
        """Get current DNS server based on platform."""
        try:
            if self.system == 'windows':
                output = subprocess.check_output(
                    ['ipconfig', '/all'], 
                    universal_newlines=True
                )
                for line in output.split('\n'):
                    if 'DNS Servers' in line:
                        return line.split(':')[-1].strip()
            elif self.system in ['linux', 'darwin']:  # Linux or MacOS
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            return line.split()[1]
            return None
        except Exception as e:
            logging.warning(f"Could not determine current DNS: {e}")
            return None

    def setup(self) -> bool:
        """Set up DNS configuration for the local DNS server."""
        try:
            if self.system == 'windows':
                # Get network adapters
                output = subprocess.check_output(
                    ['netsh', 'interface', 'show', 'interface'],
                    universal_newlines=True
                )
                # Set DNS for each enabled adapter
                for line in output.split('\n'):
                    if 'Connected' in line:
                        adapter = line.split()[-1]
                        subprocess.run([
                            'netsh', 'interface', 'ip', 'set', 'dns',
                            adapter, 'static', '127.0.0.1'
                        ])
            elif self.system == 'darwin':  # MacOS
                # Get active network service
                output = subprocess.check_output(
                    ['networksetup', '-listallnetworkservices'],
                    universal_newlines=True
                )
                for service in output.split('\n')[1:]:  # Skip first line
                    if service and not service.startswith('*'):
                        subprocess.run([
                            'networksetup', '-setdnsservers',
                            service, '127.0.0.1'
                        ])
            elif self.system == 'linux':
                # Use resolvectl if available (modern Linux)
                try:
                    subprocess.run(['resolvectl', 'dns', '0', '127.0.0.1'])
                except FileNotFoundError:
                    # Fallback to direct resolv.conf modification
                    with open('/etc/resolv.conf', 'w') as f:
                        f.write("nameserver 127.0.0.1\n")
            
            logging.info("DNS configuration updated successfully")
            return True
        except Exception as e:
            logging.error(f"Failed to set up DNS: {e}")
            return False

    def restore(self) -> bool:
        """Restore original DNS configuration."""
        try:
            if not self.original_dns:
                logging.warning("No original DNS configuration to restore")
                return False

            if self.system == 'windows':
                output = subprocess.check_output(
                    ['netsh', 'interface', 'show', 'interface'],
                    universal_newlines=True
                )
                for line in output.split('\n'):
                    if 'Connected' in line:
                        adapter = line.split()[-1]
                        subprocess.run([
                            'netsh', 'interface', 'ip', 'set', 'dns',
                            adapter, 'static', self.original_dns
                        ])
            elif self.system == 'darwin':
                output = subprocess.check_output(
                    ['networksetup', '-listallnetworkservices'],
                    universal_newlines=True
                )
                for service in output.split('\n')[1:]:
                    if service and not service.startswith('*'):
                        subprocess.run([
                            'networksetup', '-setdnsservers',
                            service, self.original_dns
                        ])
            elif self.system == 'linux':
                try:
                    subprocess.run(['resolvectl', 'dns', '0', self.original_dns])
                except FileNotFoundError:
                    with open('/etc/resolv.conf', 'w') as f:
                        f.write(f"nameserver {self.original_dns}\n")

            logging.info("Original DNS configuration restored")
            return True
        except Exception as e:
            logging.error(f"Failed to restore DNS: {e}")
            return False

class BlockerResolver:
    def __init__(self, upstream_dns="8.8.8.8", upstream_port=53):
        self.upstream_dns = upstream_dns
        self.upstream_port = upstream_port
        self.regex_patterns = [r"^.*\.google\.com$"]  # Regex patterns start with ^
        self.direct_domains = {"novafork.com", "you.com", "huggingface.co"}  # Direct domain matches

    def create_domain_pattern(self, domain):
        # Escape dots in domain to prevent regex special character interpretation
        escaped_domain = domain.replace('.', r'\.')
        # Create pattern that matches domain and all its subdomains
        return f"^(.*\.)?{escaped_domain}$"

    def resolve(self, request, handler):
        # Parse the request
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        # Convert direct domains to regex patterns and combine with existing patterns
        all_patterns = self.regex_patterns + [self.create_domain_pattern(domain) for domain in self.direct_domains]

        # Check all patterns
        for pattern in all_patterns:
            if re.match(pattern, qname):
                print(f"Blocked: {qname} matched {pattern}")
                reply = request.reply()
                reply.add_answer(RR(qname, QTYPE.A, ttl=60, rdata=A("0.0.0.0")))
                return reply
        # Forward the query to the upstream DNS server
        try:
            print(f"Forwarding: {qname}")
            upstream_request = request.pack()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(upstream_request, (self.upstream_dns, self.upstream_port))
                upstream_response, _ = sock.recvfrom(512)  # 512 bytes is the standard DNS message size
                return DNSRecord.parse(upstream_response)
        except Exception as e:
            print(f"Error forwarding query: {e}")
            reply = request.reply()
            reply.header.rcode = 2  # Server failure
            return reply

def check_privileges():
    """Check if the program has necessary privileges."""
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except Exception:
        return False

if __name__ == "__main__":
    if not check_privileges():
        logging.error("This program requires administrator/root privileges.")
        sys.exit(1)

    dns_config = DNSConfigurator()
    resolver = BlockerResolver()
    server = DNSServer(resolver, port=53, address="127.0.0.1")

    try:
        if not dns_config.setup():
            logging.error("Failed to set up DNS configuration")
            sys.exit(1)

        logging.info("Starting DNS Blocker...")
        server.start_thread()
        logging.info("DNS Blocker is running. Press Ctrl+C to stop.")
        
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logging.info("\nStopping DNS Blocker...")
        server.stop()
        dns_config.restore()
        logging.info("DNS Blocker stopped and system configuration restored.")
    except Exception as e:
        logging.error(f"Error: {e}")
        dns_config.restore()
        logging.info("System configuration restored due to error.")
        sys.exit(1)
