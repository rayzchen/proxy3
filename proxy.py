from http.server import HTTPServer, BaseHTTPRequestHandler
from http.client import HTTPSConnection
from urllib.parse import urlsplit
import subprocess
import threading
import socket
import time
import ssl
import re
import os

def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)

class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = join_with_script_dir("ca.key")
    cacert = join_with_script_dir("ca.crt")
    certkey = join_with_script_dir("cert.key")
    certdir = join_with_script_dir("certs/")
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        super().__init__(*args, **kwargs)

    def do_OPTIONS(self):
        self.send_response(200, "ok")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-Requested-With")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_CONNECT(self):
        hostname = self.path.split(":")[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip("/"), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = subprocess.Popen(["openssl", "req", "-new", "-key", self.certkey,
                                       "-subj", f"/CN={hostname}"],
                                      stdout=subprocess.PIPE)
                p2 = subprocess.Popen(["openssl", "x509", "-req", "-days", "3650",
                                       "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial",
                                       epoch, "-out", certpath],
                                      stdin=p1.stdout, stderr=subprocess.PIPE)
                p2.communicate()

        self.wfile.write(f"{self.protocol_version} 200 Connection established\r\n".encode("utf-8"))
        self.wfile.write(("Proxy-agent: %s\r\n" % self.version_string()).encode("utf-8"))
        self.wfile.write("\r\n".encode("utf-8"))

        self.sslctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.sslctx.load_cert_chain(certpath, self.certkey)
        self.connection = self.sslctx.wrap_socket(
            self.connection,
            server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get("Proxy-Connection", "")
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != "close":
            self.close_connection = False
        else:
            self.close_connection = True

    def do_GET(self):
        if self.path == 'http://proxy3.test/':
            with open(self.cacert, 'rb') as f:
                data = f.read()
            self.wfile.write(f"{self.protocol_version} 200 OK\r\n".encode("utf-8"))
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Length", len(data))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            return

        content_length = int(self.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if self.path[0] == "/":
            self.path = f"https://{self.headers['Host']}{self.path}"

        u = urlsplit(self.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + "?" + u.query if u.query else u.path)
        if netloc:
            self.headers["Host"] = netloc
        self.headers = self.filter_headers(self.headers)

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                self.tls.conns[origin] = HTTPSConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(self.headers))
            res = conn.getresponse()

            version_table = {10: "HTTP/1.0", 11: "HTTP/1.1"}
            setattr(res, "headers", res.msg)
            setattr(res, "response_version", version_table[res.version])

            # support streaming
            if not "Content-Length" in res.headers and "no-store" in res.headers.get("Cache-Control", ""):
                setattr(res, "headers", self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    print(f"{self.command} {self.path} {self.request_version} {res.status} {res.reason}")
                return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        self.headers = self.filter_headers(self.headers)
        self.wfile.write(f"{self.protocol_version} {res.status} {res.reason}\r\n".encode("utf-8"))
        for line in res.headers:
            self.wfile.write(line.encode("utf-8"))
        self.wfile.write("\r\n".encode("utf-8"))
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            print(f"{self.command} {self.path} {self.request_version} {res.status} {res.reason}")

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ("connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade")
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if "Accept-Encoding" in headers:
            ae = headers["Accept-Encoding"]
            filtered_encodings = [x for x in re.split(r",\s*", ae) if x in ("identity", "gzip", "x-gzip", "deflate")]
            headers["Accept-Encoding"] = ", ".join(filtered_encodings)

        return headers

    def relay_streaming(self, res):
        self.wfile.write(f"{self.protocol_version} {res.status} {res.reason}\r\n".encode("utf-8"))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

def main():
    addr = ("localhost", 8001)
    httpd = HTTPServer(addr, ProxyRequestHandler)
    print(f"Server running on {addr[0]}:{addr[1]}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()

