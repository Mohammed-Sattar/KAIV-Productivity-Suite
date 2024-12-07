from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer
import time

# Define a set of blocked domains
BLOCKED_DOMAINS = {
    "novafork.com",
    "google.com",
    "you.com",
    "huggingface.com"
}

class BlockerResolver:
    def resolve(self, request, handler):
        # Parse the request
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        # Check if the domain is in the blocklist
        if qname in BLOCKED_DOMAINS and qtype == "A":
            print(f"Blocked: {qname}")
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, ttl=60, rdata=A("127.0.0.1")))
            return reply

        # If not blocked, forward the query (e.g., to a public DNS server)
        # Placeholder for forwarding logic, if needed
        reply = request.reply()
        reply.header.rcode = 3  # NXDOMAIN (Non-existent domain)
        return reply

# Set up the DNS server
resolver = BlockerResolver()
server = DNSServer(resolver, port=53, address="127.0.0.1", tcp=True)

print("Starting DNS Blocker...")
try:
    server.start_thread()
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopping DNS Blocker...")
    server.stop()
