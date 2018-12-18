import socket
import sys
from optparse import OptionParser

import requests


def get_signature():
    with open("my_sign_tx", "r") as f:
        signature = f.read()
        return signature


def main(port, rec, amount):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        my_addr = s.getsockname()[0]
    my_addr += ':' + str(port)
    query = {
        'recipient': rec,
        'amount': amount,
        'signature': get_signature(),
    }
    response = requests.post('http://' + my_addr + '/transactions/new', json=query)
    print(response)


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-p", "--port", help="my port", dest='port')
    parser.add_option("-r", "--recipient", help="recipient public key", dest='rec')
    parser.add_option("-a", "--amount", help="amount of money", dest='amount')
    options, args = parser.parse_args()

    if options.amount is None or options.rec is None or options.port is None:
        print('Not enough args')
        sys.exit(1)
    options.rec = options.rec.replace("\\n", "\n")
    main(options.port, options.rec, options.amount)
