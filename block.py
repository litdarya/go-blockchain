import hashlib
import socket
import sys
import threading
import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from ecdsa import NIST256p
from ecdsa import SigningKey
from ecdsa import VerifyingKey
from flask import Flask, jsonify, request
from flask.json import JSONEncoder
from optparse import OptionParser


app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', '')


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

        return res_block

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
        outputs = list()
        res = TransactionInput(tx['output_id'])

        if tx['UTO'] is None:
            return res

        outputs.append(Deserializer.parse_transaction_output(tx['UTO']))

        return res


class SshPair:

    def __init__(self):
        pass

    @staticmethod
    # TODO: public_exponent and key_size -- fix
    # TODO: save keys somewhere
    def get_public_private():
        private_key = SigningKey.generate(curve=NIST256p)
        public_key = private_key.get_verifying_key()

        return private_key, public_key.to_pem().decode('utf-8')

    # TODO: verification
    @staticmethod
    def verify(private, public):
        return True


class Block:
    # timestamp
    # hash
    # previous hash
    # transactions
    # nonce
    # merkle_root

    def __init__(self, prev_hash):
        self.prev_hash = prev_hash
        self.timestamp = time.time()

        self.transactions = list()
        self.merkle_root = ""

        self.nonce = 0
        self.hash = self._block_hash()

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
    UTO = dict()

    def __init__(self, difficulty=2):
        self.chain = list()
        self.nodes = list()
        self.waiting_transactions = list()
        self.gen_tx = None

        BlockChain.difficulty = difficulty

    def add_to_chain(self, block):
        self.chain.append(block)

    # TODO: maybe print to json?
    def print_chain(self):
        for block in self.chain:
            print("-------")
            block.print_block()
            print("-------")

    def get_last(self):
        return self.chain[-1]

    def register_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.append(parsed_url.netloc)

    def resolve_conflicts(self):
        new_chain = None
        new_UTO = None
        max_len = len(self.chain)

        for node in self.nodes:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['Length']
                tmp_gen_tx = response.json()['gen_tx']
                tmp_chain_json = response.json()['BlockChain']
                tmp_chain = Deserializer.parse_chain(tmp_chain_json)

                tmp_UTO_json = response.json()['UTO']
                tmp_UTO = dict()

                for tx in tmp_UTO_json.items():
                    tmp_UTO[tx[0]] = Deserializer.parse_transaction_output(tx[1])

                possible_chain = self
                possible_chain.chain = tmp_chain
                possible_chain.UTO = tmp_UTO
                possible_chain.gen_tx = Deserializer.parse_transactions(tmp_gen_tx)

                if length > max_len and BlockChain.check_validity(possible_chain):
                    max_len = length
                    new_chain = tmp_chain
                    new_UTO = tmp_UTO

        if new_chain is not None:
            self.chain = new_chain
            BlockChain.UTO = new_UTO
            return True

        return False

    @staticmethod
    def check_validity(chain_sample):
        target = "0"*chain_sample.difficulty
        tmp_UTO = dict()
        tmp_UTO[chain_sample.gen_tx.outputs[0].id] = \
            chain_sample.gen_tx.outputs[0]

        for i in range(1, len(chain_sample.chain)):
            curr_block = chain_sample.chain[i]
            prev_block = chain_sample.chain[i - 1]

            if curr_block.hash != curr_block._block_hash():
                print("Hash of block is incorrect", curr_block.hash)
                return False

            if prev_block.hash != curr_block.prev_hash:
                print("Previous hash is incorrect")
                return False

            if curr_block.hash[:chain_sample.difficulty] != target:
                print("A block is not mined")
                return False

            for tx in curr_block.transactions:
                if not tx.verify_signature():
                    print("Transaction with wrong signature")
                    return tx

                for tx_input in tx.inputs:
                    if tx_input.output_id in tmp_UTO:
                        tmp_UTO.pop(tx_input.output_id)
                        # print("Input transaction is missing ", tx_input.output_id)
                        # return False
                    # print(tx_input.output_id)
                    # if tx_input.UTO.value != tmp_UTO[tx_input.output_id].value:
                    #     print("Invalid input transaction value")
                    #     return False

                for tx_output in tx.outputs:
                    tmp_UTO[tx_output.id] = tx_output

                if tx.outputs[0].recipient != tx.recipient:
                    print("Wrong recipient")
                    return False

                if tx.outputs[1].recipient != tx.sender:
                    print("Wrong sender")
                    return False

        return True


class Wallet:
    # public key
    # private key
    # UTO - unspent transactions of this owner

    def __init__(self):
        self.__generate_key_pair()
        self.UTO = dict()

    def __generate_key_pair(self):
        self.private_key, self.public_key = SshPair.get_public_private()

    def get_balance(self):
        res = 0
        for tx in BlockChain.UTO.values():
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


class Transaction:
    # id
    # sender
    # recipient
    # signature
    # value

    # inputs
    # outputs

    # sequence

    def __init__(self, sender, recipient, value, inputs, sequence=0):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.inputs = inputs
        self.signature = None
        self.outputs = list()
        self.sequence = sequence
        self.id = self.__calculate_hash()

    # TODO: remove get hash from Block class
    def __calculate_hash(self):
        self.sequence += 1
        # line = self.sender.to_pem().decode('utf-8') + \
        #     self.recipient.to_pem().decode('utf-8') + \
        #     str(self.value) + str(self.sequence)
        line = self.sender + self.recipient + \
            str(self.value) + str(self.sequence)

        return Block.get_hash(line)

    # TODO: line to self.data but with inputs
    def generate_signature(self, private_key):
        # line = self.sender.to_pem() + self.recipient.to_pem() + bytearray(self.value)
        line = (self.sender + self.recipient + str(self.value)).encode()
        sk = SigningKey.from_string(private_key.to_string(), curve=NIST256p)
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
                tx.UTO = BlockChain.UTO.get(tx.output_id)

        if self.get_tx_value() < BlockChain.min_input:
            print("Inputs value is too small")
            return False

        left = self.get_tx_value() - self.value
        print("left ", left)
        tx_id = self.__calculate_hash()
        self.outputs.append(TransactionOutput(self.recipient, self.value, tx_id))
        self.outputs.append(TransactionOutput(self.sender, left, tx_id))

        for out_tx in self.outputs:
            BlockChain.UTO[out_tx.id] = out_tx

        for tx in self.inputs:
            if tx.UTO is not None:
                BlockChain.UTO.pop(tx.output_id)

        return True


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
        if isinstance(obj, TransactionInput):
            return {
                'output_id': obj.output_id,
                'UTO': obj.UTO,
            }
        return super(MyJSONEncoder, self).default(obj)


user_wallet = Wallet()
gen_wallet = Wallet()
gen_tx = None
mine_seq = 0
chain = BlockChain()


def init():
    global gen_tx
    gen_tx = Transaction(gen_wallet.public_key,
                         user_wallet.public_key, 100, None)
    gen_tx.generate_signature(gen_wallet.private_key)
    gen_tx.id = '0'
    gen_tx.outputs.append(TransactionOutput(gen_tx.recipient, gen_tx.value, gen_tx.id))
    BlockChain.UTO[gen_tx.outputs[0].id] = gen_tx.outputs[0]

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


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'gen_tx': chain.gen_tx,
        'UTO': chain.UTO,
        'BlockChain': chain.chain,
        'Length': len(chain.chain),
    }
    return jsonify(response), 200


@app.route('/balance', methods=['GET'])
def balance():
    res = user_wallet.get_balance()
    line = "Your balance is " + str(res)
    return line


@app.route('/validity', methods=['GET'])
def verify_chain():
    if BlockChain.check_validity(chain) is True:
        return "The chain is valid"
    return "The chain is corrupted"


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['recipient', 'amount']

    if not all(k in values for k in required):
        return 'Missing values', 400

    tx = user_wallet.send_money(values['recipient'], values['amount'])
    if tx is None:
        return "Not enough money"

    chain.waiting_transactions.append(tx)

    response = {'message': f'Transaction will be added to some block'}

    return jsonify(response), 201


@app.route('/mine', methods=['GET'])
def mine():
    global mine_seq
    last_block = chain.get_last()
    new_block = Block(last_block.hash)

    if len(chain.waiting_transactions) == 0:
        return "Sorry, nothing to mine"

    for tx in chain.waiting_transactions:
        new_block.add_transaction(tx)
        chain.waiting_transactions.remove(tx)

    motive_tx = Transaction(gen_wallet.public_key,
                            user_wallet.public_key, 1, None, mine_seq)
    mine_seq += 1
    motive_tx.generate_signature(gen_wallet.private_key)
    motive_tx.outputs.append(TransactionOutput(motive_tx.recipient, motive_tx.value, gen_tx.id))
    BlockChain.UTO[motive_tx.outputs[0].id] = motive_tx.outputs[0]
    # new_block.add_transaction(motive_tx)
    new_block.mine_block(chain.difficulty)
    # should be a sort of broadcast
    print(new_block)
    chain.add_to_chain(new_block)
    print(len(chain.chain))
    return "you mined!"


@app.route('/node/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    node = values.get('node')
    if node is None:
        return "Error: Please supply a valid list of nodes", 400

    chain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(chain.nodes),
    }
    return jsonify(response), 201


@app.route('/node/unregister', methods=['POST'])
def unregister_nodes():
    values = request.get_json()

    node = values.get('node')
    if node is None:
        return "Error: Please supply a valid list of nodes", 400

    chain.chain.remove(node)

    response = {
        'message': 'The node has been removed',
        'removed_node': node,
    }
    return jsonify(response), 201


app.json_encoder = MyJSONEncoder


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = chain.resolve_conflicts()

    if replaced:
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


class AsyncTask(threading.Thread):
    def __init__(self, server):
        super().__init__()
        self.server = 'http://' + str(server)
        self.my_addr = 'http://' + \
                       socket.gethostbyname(socket.gethostname()) + \
                       ':'

    def run(self):
        global port
        time.sleep(2)
        query = {
            'node': self.my_addr + str(port),
            'public_key': user_wallet.public_key,
        }
        requests.post(self.server + '/new', json=query)


def register_myself(server):
    async_task = AsyncTask(server)
    async_task.run()


port = 5001


def start_app():
    global port
    while True:
        try:
            app.run(debug=True, use_reloader=False, host='0.0.0.0', port=port)
        except OSError:
            pass
        port += 5


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-s", "--server", help="server address", dest='server')
    options, args = parser.parse_args()
    if options.server is None:
        print('Not enough args')
    server_addr = options.server
    init()
    threading.Thread(target=start_app).start()
    threading.Thread(target=register_myself, args=(server_addr,)).start()

