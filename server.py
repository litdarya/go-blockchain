from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request
from uuid import uuid4

import tempfile

import os

app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', '')

local_nodes = dict()


def broadcast_delete(broken_node):
    for addr in local_nodes:
        query = {
            'node': broken_node,
        }

        try:
            requests.post(f'http://{addr}/node/unregister', query)
        except:
            continue


def broadcast_new(new_node):
    for addr in local_nodes:
        query = {
            'node': new_node,
        }

        if new_node == addr:
            continue

        try:
            response = requests.post(f'http://{addr}/node/register', json=query)
        except:
            broadcast_delete(addr)


def broadcast_to_new(new_node):
    for addr in local_nodes:
        query = {
            'node': addr,
        }

        if new_node == addr:
            continue

        try:
            requests.post(f'http://{new_node}/node/register', json=query)
        except:
            broadcast_delete(new_node)


@app.route('/new', methods=['POST'])
def new_node():
    values = request.get_json()
    node = values.get('node')
    public_key = values.get('public_key')

    if node is None or public_key is None:
        return "Error: Please supply a valid node addr", 400

    parsed_url = urlparse(node)
    broadcast_new(parsed_url.netloc)
    broadcast_to_new(parsed_url.netloc)
    local_nodes[parsed_url.netloc] = public_key
    response = {
        'message': 'registered',
    }
    return jsonify(response), 201


@app.route('/remove', methods=['POST'])
def remove_node():
    values = request.get_json()

    node = values.get('node')
    if node is None:
        return "Error: Please supply a valid list of nodes", 400

    parsed_url = urlparse(node)

    if parsed_url.netloc in local_nodes:
        local_nodes.pop(parsed_url.netloc)
        broadcast_delete(parsed_url.netloc)

    return "ok", 200


@app.route('/logs', methods=['POST'])
def get_logs():
    if not os.path.exists('tmp_logs'):
        os.makedirs('tmp_logs')

    values = request.get_data()

    tf = tempfile.NamedTemporaryFile(dir='tmp_logs')
    with open(tf.name, 'w+') as f:
        f.write(values.decode('utf-8'))
    return "ok", 200


@app.route('/getall', methods=['GET'])
def all_users():
    return jsonify(local_nodes), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
