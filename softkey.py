# softkey.py - A UDP server for dispatching calls to a SoftKey2.
#
# TODO Rewrite as an RPC service.
import otp
import pickle
import SocketServer

test_key = '\x00' * 32
test_id = 'fellas'
ct = 0
host = 'localhost'
port = 8084

soft_key = otp.SoftKey2(test_key, test_id, ct)

class SoftKey2UDPHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        client = self.client_address

        try:
            (iface, inputs) = pickle.loads(data)
            print iface
            (resp, err) = soft_key.dispatch(iface, inputs)
            if err != None:
                print 'error:', err
            socket.sendto(pickle.dumps((resp,err)), client)

        except err:
            print 'pickle error:', err
            socket.sendto(pickle.dumps((None,err)), client)

if __name__ == '__main__':
    server = SocketServer.UDPServer((host, port), SoftKey2UDPHandler)
    server.serve_forever()
