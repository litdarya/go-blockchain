import hashlib
import json
import os
import socket
import sys
import threading
import time
from optparse import OptionParser
from urllib.parse import urlparse
from uuid import uuid4

import requests
from ecdsa import SigningKey, NIST256p
from ecdsa import VerifyingKey
from flask import Flask, jsonify, request
from flask.json import JSONEncoder

app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', '')


class SshPair:

    def __init__(self):
        pass

    @staticmethod
    def get_public_private():
        private_key = SigningKey.generate(curve=NIST256p)
        public_key = private_key.get_verifying_key()

        return private_key.to_pem().decode('utf-8'), public_key.to_pem().decode('utf-8')


class MyJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, TransactionOutput):
            return {
                'recipient': obj.recipient,
                'value': obj.value,
                'parent_transaction_id': obj.parent_transaction_id,
                'id': obj.id
            }
        if isinstance(obj, Block):
            return {
                'prev_hash': obj.prev_hash,
                'timestamp': obj.timestamp,
                'transactions': obj.transactions,
                'merkle_root': obj.merkle_root,
                'hash': obj.hash,
                'nonce': obj.nonce,
                'coinbase_tx': obj.coinbase_tx,
            }
        if isinstance(obj, Transaction):
            return {
                'sender': obj.sender,
                'recipient': obj.recipient,
                'value': obj.value,
                'inputs': obj.inputs,
                'signature': obj.signature,
                'outputs': obj.outputs,
                'sequence': obj.sequence,
                'id': obj.id,
            }
        if isinstance(obj, CoinbaseTransaction):
            return {
                'recipient': obj.recipient,
                'value': obj.value,
                'block_hash': obj.block_hash,
                'output': obj.output,
                'sequence': obj.sequence,
            }
        if isinstance(obj, TransactionInput):
            return {
                'output_id': obj.output_id,
                'UTO': obj.UTO,
            }
        return super(MyJSONEncoder, self).default(obj)


app.json_encoder = MyJSONEncoder


class Deserializer:
    def __init__(self):
        pass

    @staticmethod
    def parse_chain(chain):
        res_chain = list()
        for ch in chain:
            res_chain.append(Deserializer.parse_block(ch))

        return res_chain

    @staticmethod
    def parse_block(block_json):
        res_block = Block(block_json['prev_hash'])
        res_block.timestamp = block_json['timestamp']
        res_block.merkle_root = block_json['merkle_root']
        res_block.hash = block_json['hash']
        res_block.nonce = block_json['nonce']

        for tx in block_json['transactions']:
            if tx is not None:
                res_block.transactions.append(Deserializer.parse_transactions(tx))

        res_block.coinbase_tx = Deserializer.parse_coinbase(block_json['coinbase_tx'])

        return res_block

    @staticmethod
    def parse_coinbase(tx):
        if tx is None:
            return None

        res = CoinbaseTransaction(tx['recipient'], tx['value'], tx['block_hash'])
        res.output = Deserializer.parse_transaction_output(tx['output'])
        res.sequence = tx['sequence']
        return res

    @staticmethod
    def parse_transactions(tx):
        inputs = list()
        outputs = list()

        if tx['inputs'] is not None:
            for i in tx['inputs']:
                inputs.append(Deserializer.parse_transaction_input(i))

        for o in tx['outputs']:
            outputs.append(Deserializer.parse_transaction_output(o))

        res_tx = Transaction(tx['sender'], tx['recipient'], float(tx['value']), inputs)
        res_tx.sequence = tx['sequence']
        res_tx.id = tx['id']
        res_tx.signature = tx['signature']
        res_tx.outputs = outputs
        return res_tx

    @staticmethod
    def parse_transaction_output(tx):
        res = TransactionOutput(tx['recipient'], float(tx['value']),
                                tx['parent_transaction_id'])
        res.id = tx['id']

        return res

    @staticmethod
    def parse_transaction_input(tx):
        res = TransactionInput(tx['output_id'])

        if tx['UTO'] is None:
            return res

        res.UTO = Deserializer.parse_transaction_output(tx['UTO'])
        return res


class Block:
    # timestamp
    # hash
    # previous hash
    # transactions
    # nonce
    # merkle_root
    # coinbase tx

    def __init__(self, prev_hash):
        self.prev_hash = prev_hash
        self.timestamp = time.time()

        self.transactions = list()
        self.merkle_root = ""

        self.nonce = 0
        self.hash = self._block_hash()

        self.coinbase_tx = None

    def _block_hash(self):
        line = self.prev_hash + str(self.timestamp) + str(self.nonce) + self.merkle_root
        return Block.get_hash(line)

    # TODO: move from Block class to some static class
    @staticmethod
    def get_hash(line):
        res = hashlib.sha256()
        res.update(line.encode('utf-8'))
        return res.hexdigest()

    def print_block(self):
        print("Timestamp: {0}\nHash: {1}".format(self.timestamp, self.hash))

    # TODO: get normal merkle tree
    def __get_merkle_root(self):
        prev_layer = list()
        for tx in self.transactions:
            prev_layer.append(tx.id)

        new_layer = prev_layer
        count = len(self.transactions)
        while count > 1:
            new_layer = list()
            for i in range(1, len(prev_layer)):
                new_layer.append(Block.get_hash(prev_layer[i - 1] + prev_layer[i]))
            count = len(new_layer)
            prev_layer = new_layer

        merkle_root = ''
        if len(new_layer) == 1:
            merkle_root = new_layer[0]

        self.merkle_root = merkle_root
        return merkle_root

    def mine_block(self, difficulty):
        self.__get_merkle_root()
        target = "0"*difficulty
        tmp_hash = self.hash

        while tmp_hash[:difficulty] != target:
            self.nonce += 1
            tmp_hash = self._block_hash()

        self.hash = tmp_hash
        self.coinbase_tx.block_hash = self.hash
        print("Successfully mined {0}".format(tmp_hash))

    def add_transaction(self, transaction):
        if transaction is None:
            return False

        if self.prev_hash is not '0':
            if not transaction.process_transaction():
                print('Transaction is discarded')
                return False
        self.transactions.append(transaction)
        print('Transaction was added to a block')
        return True


class BlockChain:
    # chain = list()
    # UTOs
    # nodes
    min_input = 0
    difficulty = 0

    def __init__(self, difficulty=2):
        self.chain = list()
        self.nodes = list()
        self.waiting_transactions = list()
        self.gen_tx = None
        self.UTO = dict()

        BlockChain.difficulty = difficulty

    def add_to_chain(self, block):
        self.chain.append(block)

    def get_last(self):
        if len(self.chain) == 0:
            return None
        return self.chain[-1]

    def register_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.append(parsed_url.path)

    def resolve_conflicts(self, nodes):
        new_chain = None
        new_UTO = None
        new_waiting = None
        max_len = len(self.chain)

        for node in nodes:
            max_len, new_chain, new_UTO, new_waiting = self.resolve(max_len, new_chain,
                                                                    new_UTO, new_waiting, node)

        if new_chain is not None:
            self.chain = new_chain
            self.waiting_transactions = new_waiting
            self.UTO = new_UTO
            return True

        return False

    def resolve(self, max_len, new_chain, new_UTO, new_waiting, node):
        response = requests.get(f'http://{node}/chain')

        if response.status_code == 200:
            length = response.json()['Length']
            tmp_gen_tx = response.json()['gen_tx']
            tmp_chain_json = response.json()['BlockChain']
            tmp_chain = Deserializer.parse_chain(tmp_chain_json)
            tmp_waiting_json = response.json()['Waiting']

            if len(tmp_chain) == 0:
                return max_len, new_chain, new_UTO, new_waiting

            tmp_waiting = list()
            for tx in tmp_waiting_json:
                tmp_waiting.append(Deserializer.parse_transactions(tx))

            tmp_UTO_json = response.json()['UTO']
            tmp_UTO = dict()

            for tx in tmp_UTO_json.items():
                tmp_UTO[tx[0]] = Deserializer.parse_transaction_output(tx[1])

            possible_chain = self
            possible_chain.chain = tmp_chain
            possible_chain.UTO = tmp_UTO
            possible_chain.waiting_transactions = tmp_waiting

            if tmp_gen_tx is not None:
                possible_chain.gen_tx = Deserializer.parse_transactions(tmp_gen_tx)

            if length > max_len:
                check, tmp_waiting = BlockChain.check_validity(possible_chain)
                if check:
                    max_len = length
                    new_chain = tmp_chain
                    new_UTO = tmp_UTO
                    new_waiting = tmp_waiting

        return max_len, new_chain, new_UTO, new_waiting

    @staticmethod
    def check_validity(chain_sample):
        target = "0"*chain_sample.difficulty
        tmp_UTO = dict()
        tmp_UTO[chain_sample.gen_tx.outputs[0].id] = \
            chain_sample.gen_tx.outputs[0]

        tmp_waiting = list(set(chain.waiting_transactions)
                           | set(chain_sample.waiting_transactions))

        for i in range(1, len(chain_sample.chain)):
            curr_block = chain_sample.chain[i]
            prev_block = chain_sample.chain[i - 1]

            if curr_block.hash != curr_block._block_hash():
                print("Hash of block is incorrect", curr_block.hash)
                return False, None

            if prev_block.hash != curr_block.prev_hash:
                print("Previous hash is incorrect")
                return False, None

            if curr_block.hash[:chain_sample.difficulty] != target:
                print("A block is not mined")
                return False, None

            if curr_block.coinbase_tx.block_hash != curr_block.hash:
                print("Wrong coinbase")
                return False, None

            tmp_UTO[curr_block.coinbase_tx.output.id] = curr_block.coinbase_tx.output

            for tx in curr_block.transactions:
                if tx in tmp_waiting:
                    tmp_waiting.remove(tx)

                if not tx.verify_signature():
                    print("Transaction with wrong signature")
                    return tx

                for tx_input in tx.inputs:
                    if tx_input.output_id not in tmp_UTO:
                        print("Input transaction is missing ", tx_input.output_id)
                        return False, None

                    if tx_input.UTO.value != tmp_UTO[tx_input.output_id].value:
                        print("Invalid input transaction value")
                        return False, None
                    tmp_UTO.pop(tx_input.output_id)

                for tx_output in tx.outputs:
                    tmp_UTO[tx_output.id] = tx_output

                if tx.outputs[0].recipient != tx.recipient:
                    print("Wrong recipient")
                    return False, None

                if tx.outputs[1].recipient != tx.sender:
                    print("Wrong sender")
                    return False, None

        return True, tmp_waiting


class TransactionOutput:
    # id
    # recipient
    # value
    # parent_transaction_id

    def __init__(self, recipient, value, parent_transaction_id):
        self.recipient = recipient
        self.value = value
        self.parent_transaction_id = parent_transaction_id

        line = recipient + str(value) + str(parent_transaction_id)
        self.id = Block.get_hash(line)

    def my_coin(self, public_key):
        return public_key == self.recipient


class TransactionInput:
    # output_id
    # unspent_transaction_output -- UTO

    def __init__(self, output_id):
        self.output_id = output_id
        self.UTO = None


class CoinbaseTransaction:
    sequence = 0

    def __init__(self, recipient, value, block_hash):
        self.recipient = recipient
        self.value = value
        self.block_hash = block_hash
        self.output = None

    def __calculate_hash(self):
        CoinbaseTransaction.sequence += 1
        line = self.recipient + \
            str(self.value) + str(self.sequence)

        return Block.get_hash(line)

    def process_transaction(self):
        tx_id = self.__calculate_hash()
        self.output = TransactionOutput(self.recipient, self.value, tx_id)
        chain.UTO[self.output.id] = self.output
        return True


class Transaction:
    # id
    # sender
    # recipient
    # signature
    # value

    # inputs
    # outputs

    # sequence
    sequence = 0

    def __init__(self, sender, recipient, value, inputs):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.inputs = inputs
        self.signature = None
        self.outputs = list()
        self.id = self.__calculate_hash()

    # TODO: remove get hash from Block class
    def __calculate_hash(self):
        Transaction.sequence += 1
        line = self.sender + self.recipient + \
            str(self.value) + str(self.sequence)

        if self.inputs is not None:
            for inp in self.inputs:
                line += str(inp.output_id)

        return Block.get_hash(line)

    def generate_signature(self, private_key):
        line = (self.sender + self.recipient + str(self.value)).encode()
        sk = SigningKey.from_pem(private_key.encode())
        self.signature = sk.sign(line).hex()
        return self.signature

    def verify_signature(self):
        line = (self.sender + self.recipient + str(self.value)).encode()
        vk = VerifyingKey.from_pem(self.sender)
        return vk.verify(bytes.fromhex(self.signature), line)

    def get_tx_value(self):
        res = 0

        for tx in self.inputs:
            if tx.UTO is not None:
                res += tx.UTO.value

        return res

    def process_transaction(self):
        if not self.verify_signature():
            print("Verifying transaction failed")
            return False

        if self.inputs is not None:
            # check if transaction is not spent
            for tx in self.inputs:
                tx.UTO = chain.UTO.get(tx.output_id)

        if self.get_tx_value() < BlockChain.min_input:
            print("Inputs value is too small")
            return False

        left = self.get_tx_value() - self.value
        print("left ", left)
        tx_id = self.__calculate_hash()
        self.outputs.append(TransactionOutput(self.recipient, self.value, tx_id))
        self.outputs.append(TransactionOutput(self.sender, left, tx_id))

        for out_tx in self.outputs:
            chain.UTO[out_tx.id] = out_tx

        for tx in self.inputs:
            if tx.UTO is not None:
                chain.UTO.pop(tx.output_id)

        return True


class Wallet:
    # public key
    # private key
    # UTO - unspent transactions of this owner

    def __init__(self):
        self.__generate_key_pair()
        self.__generate_signature()
        self.UTO = dict()

    def __generate_key_pair(self):
        if os.path.isfile('id_rsa') and os.path.isfile('id_rsa.pub'):
            with open("id_rsa", "r") as f:
                self.private_key = f.read()

            with open("id_rsa.pub", "r") as f:
                self.public_key = f.read()

            return

        self.private_key, self.public_key = SshPair.get_public_private()

        with open("id_rsa", "w+") as f:
            f.write(self.private_key)

        with open("id_rsa.pub", "w+") as f:
            f.write(self.public_key)

    def __generate_signature(self):
        if os.path.isfile('my_sign_tx') :
            with open("my_sign_tx", "r") as f:
                self.signature = f.read()

            return

        line = self.public_key.encode()
        sk = SigningKey.from_pem(self.private_key)
        self.signature = sk.sign(line).hex()

        with open("my_sign_tx", "w+") as f:
            f.write(self.signature)

    def verify(self, signature):
        vk = VerifyingKey.from_pem(self.public_key)
        return vk.verify(bytes.fromhex(signature), self.public_key.encode())

    def get_balance(self):
        res = 0
        for tx in chain.UTO.values():
            if tx.my_coin(self.public_key):
                self.UTO[tx.id] = tx
                res += tx.value

        return res

    def send_money(self, recipient, value):
        if self.get_balance() < value:
            print("Can not send a transaction, not enough money")
            return None

        inputs = list()
        money_sum = 0

        for tx in self.UTO.values():
            money_sum += tx.value
            inputs.append(TransactionInput(tx.id))

            if money_sum > value:
                break

        new_tx = Transaction(self.public_key, recipient, float(value), inputs)
        new_tx.generate_signature(self.private_key)

        for tx in inputs:
            self.UTO.pop(tx.output_id)

        return new_tx


chain = BlockChain()
user_wallet = Wallet()
gen_wallet = Wallet()
gen_tx = None


def init():
    global gen_tx, user_wallet, gen_wallet

    gen_tx = Transaction(gen_wallet.public_key,
                         user_wallet.public_key, 100, None)
    gen_tx.generate_signature(gen_wallet.private_key)
    gen_tx.id = '0'
    gen_tx.outputs.append(TransactionOutput(gen_tx.recipient, gen_tx.value, gen_tx.id))
    chain.UTO[gen_tx.outputs[0].id] = gen_tx.outputs[0]

    gen_block = Block('0')
    gen_block.add_transaction(gen_tx)
    chain.gen_tx = gen_tx
    chain.add_to_chain(gen_block)


@app.route('/whoami', methods=['GET'])
def name():
    print(user_wallet.public_key)
    response = {
        'public_key': user_wallet.public_key,
    }
    return jsonify(response), 200


@app.route('/balance', methods=['GET'])
def balance():
    res = user_wallet.get_balance()
    line = "Your balance is " + str(res)
    return line


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'gen_tx': chain.gen_tx,
        'UTO': chain.UTO,
        'BlockChain': chain.chain,
        'Length': len(chain.chain),
        'Waiting': chain.waiting_transactions,
    }
    return jsonify(response), 200


@app.route('/validity', methods=['GET'])
def verify_chain():
    if chain.check_validity(chain)[0] is True:
        return "The chain is valid"
    return "The chain is corrupted"


def broadcast_tx(tx):
    global my_addr, port
    query = {
        'new_tx': tx,
    }
    for node in chain.nodes:
        data = jsonify(query).data.decode('utf-8')
        test = json.dumps(query, cls=MyJSONEncoder)
        requests.post('http://' + node + '/nodes/new_tx',
                      data=json.dumps(query, cls=MyJSONEncoder),
                      headers={'Content-Type': 'application/json'})


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['recipient', 'amount', 'signature']

    if not all(k in values for k in required):
        return "Missing values", 400

    if not user_wallet.verify(values['signature']):
        return "Access denied", 400

    tx = user_wallet.send_money(values['recipient'], float(values['amount']))
    if tx is None:
        return "Not enough money", 400

    chain.waiting_transactions.append(tx)
    broadcast_tx(tx)
    response = {'message': f'Transaction will be added to some block'}

    return jsonify(response), 201


@app.route('/nodes/new_tx', methods=['POST'])
def waiting_tx():
    values = request.get_json()
    new_tx = values.get('new_tx')
    if new_tx is None:
        return "Error: Please supply a valid transaction", 400

    new_tx = Deserializer.parse_transactions(new_tx)

    if new_tx not in chain.waiting_transactions:
        chain.waiting_transactions.append(new_tx)

    return "ok", 200


def broadcast_chain():
    global my_addr, port
    query = {
        'node': my_addr + ':' + str(port),
    }
    for node in chain.nodes:
        try:
            requests.post('http://' + node + '/nodes/update_chain', json=query)
        except:
            chain.nodes.remove(node)


@app.route('/mine', methods=['GET'])
def mine():
    last_block = chain.get_last()
    new_block = Block(last_block.hash)

    if len(chain.waiting_transactions) == 0:
        return "Sorry, nothing to mine"

    new_block.add_transaction(chain.waiting_transactions[0])
    chain.waiting_transactions.pop(0)

    new_block.coinbase_tx = CoinbaseTransaction(user_wallet.public_key, 1, new_block.hash)
    new_block.coinbase_tx.process_transaction()
    new_block.mine_block(chain.difficulty)

    chain.add_to_chain(new_block)

    broadcast_chain()

    return "you mined!"


@app.route('/node/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    node = values.get('node')
    if node is None:
        return "Error: Please supply a valid list of nodes", 400

    chain.register_node(node)
    return "ok", 200


@app.route('/node/unregister', methods=['POST'])
def unregister_nodes():
    values = request.get_json()

    node = values.get('node')
    if node is None:
        return "Error: Please supply a valid list of nodes", 400

    chain.chain.remove(node)

    return "ok", 200


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = chain.resolve_conflicts(chain.nodes)

    if replaced:
        send_logs()
        response = {
            'message': 'Our chain was replaced',
            'new_chain': chain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': chain.chain
        }

    return jsonify(response), 200


@app.route('/nodes/update_chain', methods=['POST'])
def consensus_one_node():
    values = request.get_json()

    node = values.get('node')

    if node is None:
        return "Error: Please supply a validlist of nodes", 400

    if node not in chain.nodes:
        chain.nodes.append(node)

    replaced = chain.resolve_conflicts([node])

    if replaced:
        send_logs()
        response = {
            'message': 'Our chain was replaced',
            'new_chain': chain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': chain.chain
        }

    return jsonify(response), 200


my_addr = 0
port = 5001


class AsyncTask(threading.Thread):
    def __init__(self, server):
        super().__init__()
        self.server = 'http://' + str(server)
        global my_addr
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            my_addr = s.getsockname()[0]

        self.my_addr = 'http://' + \
                       my_addr + \
                       ':'

    def run(self):
        global port
        time.sleep(2)
        query = {
            'node': self.my_addr + str(port),
            'public_key': user_wallet.public_key,
        }
        try:
            response = requests.post(self.server + '/new', json=query)

            if response.status_code == 201:
                try:
                    requests.get(self.my_addr + str(port) + '/nodes/resolve')
                except:
                    print("Nodes are not available...")
        except:
            print("Server is not available...")


def register_myself(server):
    async_task = AsyncTask(server)
    async_task.run()


def start_app():
    global port
    while True:
        try:
            app.run(debug=True, use_reloader=False, host='0.0.0.0', port=port)
        except OSError:
            pass
        port += 5


def send_logs():
    query = {
        'timestamp': time.time(),
        'addr': my_addr,
        'port': port,
        'new_chain': chain.chain,
    }

    requests.post('http://' + server_addr + '/logs',
                  data=json.dumps(query, cls=MyJSONEncoder),
                  headers={'Content-Type': 'application/json'})


server_addr = None


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-s", "--server", help="server address", dest='server')
    parser.add_option("-m", "--master", help="am i master-node", dest='master')
    options, args = parser.parse_args()
    if options.server is None:
        print('Not enough args')
        sys.exit(1)

    server_addr = options.server
    if options.master is not None:
        init()

    threading.Thread(target=start_app).start()
    threading.Thread(target=register_myself, args=(server_addr,)).start()


