from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer
import socket
import re

# Define your blocklist with regex patterns and direct domains
regex_patterns = [r"^.*\.google\.com$"]  # Regex patterns start with ^
direct_domains = {"novafork.com", "you.com", "huggingface.co"}  # Direct domain matches

class BlockerResolver:
    def __init__(self, upstream_dns="8.8.8.8", upstream_port=53):
        self.upstream_dns = upstream_dns
        self.upstream_port = upstream_port

    def resolve(self, request, handler):
        # Parse the request
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        # First check direct domain matches
        if qname in direct_domains:
            print(f"Blocked (direct match): {qname}")
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, ttl=60, rdata=A("0.0.0.0")))
            return reply

        # Then check regex patterns
        for pattern in regex_patterns:
            if re.match(pattern, qname):
                print(f"Blocked (regex match): {qname}")
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

# Set up the DNS server
resolver = BlockerResolver()
server = DNSServer(resolver, port=53, address="127.0.0.1")

print("Starting DNS Blocker...")
try:
    server.start_thread()
    while True:
        pass  # Keep the script running
except KeyboardInterrupt:
    print("\nStopping DNS Blocker...")
    server.stop()
