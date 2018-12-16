from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request
from uuid import uuid4

app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', '')

local_nodes = dict()


def broadcast_delete(broken_node):
    for addr in local_nodes:
        query = {
            'node': broken_node,
        }

        requests.post(f'http://{addr}/node/unregister', query)


def broadcast_new(new_node):
    for addr in local_nodes:
        query = {
            'node': new_node,
        }
        response = requests.post(f'http://{addr}/node/register', query)
        i = 0

        while response != 200 and i < 10:
            response = requests.post(f'http://{addr}/node/register', query)
            i += 1

        if response != 200:
            broadcast_delete(addr)


@app.route('/new', methods=['POST'])
def new_node():
    values = request.get_json()
    node = values.get('node')

    if node is None:
        return "Error: Please supply a valid node addr", 400
    parsed_url = urlparse(node)
    print(parsed_url)
    print(parsed_url.netloc)
    response = requests.get(f'http://{parsed_url.netloc}/whoami')
    print(response.status_code)
    if response.status_code == 200:
        broadcast_new(parsed_url.netloc)
        local_nodes[parsed_url] = response.json()['public_key']
        response = {
            'message': 'OK',
        }
        return jsonify(response), 201
    return None, 400


@app.route('/exit', methods=['POST'])
def remove_node():
    values = request.get_json()

    node = values.get('node')
    if node is None:
        return "Error: Please supply a valid list of nodes", 400

    parsed_url = urlparse(node)

    if parsed_url in local_nodes:
        local_nodes.pop(parsed_url)
        broadcast_delete(parsed_url)

    return "ok", 200


@app.route('/logs', methods=['POST'])
def get_logs():
    pass


@app.route('/getall', methods=['GET'])
def all_users():
    response = dict()
    for addr, pub in local_nodes:
        response[addr] = pub
    return response, 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
