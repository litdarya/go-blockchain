import time
from optparse import OptionParser

import requests


def main(node, t=5):
    while True:
        requests.get('http://' + node + '/mine')
        time.sleep(t)


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-a", "--address", help="my address", dest='address')
    parser.add_option("-i", "--interval", help="interval between mining", dest='interval')
    options, args = parser.parse_args()

    if options.address is None:
        print('Not enough args')

    node = options.address
    if options.interval is not None:
        main(node, options.interval)
    else:
        main(node)
