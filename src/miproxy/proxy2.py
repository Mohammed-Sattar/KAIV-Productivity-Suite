import http.server
import socketserver
import ssl
import logging
import subprocess
import os
import dns.message
import dns.query

# Configure logging
logging.basicConfig(level=logging.INFO)

class Proxy(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"Received GET request for {self.path}")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'GET request received')

    def do_POST(self):
        logging.info(f"Received POST request for {self.path}")
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        logging.info(f"POST data: {post_data.decode('utf-8')}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'POST request received')

def setup_iptables():
    try:
        # Flush existing rules
        subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
        # Redirect HTTP traffic (port 80)
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8080"], check=True)
        # Redirect HTTPS traffic (port 443)
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8080"], check=True)
        logging.info("iptables rules set up successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error setting up iptables: {e}")
        exit(1)

def run(server_class=http.server.HTTPServer, handler_class=Proxy, port=8080):
    setup_iptables()
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.socket = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).wrap_socket(httpd.socket, server_side=True, certfile='path/to/cert.pem', keyfile='path/to/key.pem')
    logging.info(f'Starting proxy on port {port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run()
