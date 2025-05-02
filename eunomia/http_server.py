from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><head><title>You hit the server</title></head><body><h1>Hello from the server!</h1></body></html>")

if __name__ == '__main__':
    server_address = ('', 8000) #listen on all interfaces, port 8000
    httpd = HTTPServer(server_address, SimpleHandler)
    print(f"Serving on port {8000}...")
    httpd.serve_forever()
