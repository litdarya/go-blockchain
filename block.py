import json
import time
import hashlib
from urllib.parse import urlparse
from textwrap import dedent

from ecdsa import SigningKey
from ecdsa import NIST256p
from ecdsa import VerifyingKey

from flask import Flask, jsonify, request
from uuid import uuid4
import requests


app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', '')


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


class ProofOfWeight:
    pass


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

        self.__nonce = 0
        self.hash = self._block_hash()

    def _block_hash(self):
        line = self.prev_hash + str(self.timestamp) + str(self.__nonce) + self.merkle_root
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
            self.__nonce += 1
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
        self.nodes = set()
        self.waiting_transactions = list()

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
        self.nodes.add(parsed_url.netloc)

    def resolve_conflicts(self):
        new_chain = None
        new_UTO = None
        max_len = len(self.chain)

        for node in self.nodes:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                tmp_UTO = response.json()['UTO']
                length = response.json()['length']
                tmp_chain = response.json()['chain']

                if length > max_len and BlockChain.valid_chain(tmp_chain):
                    max_len = length
                    new_chain = tmp_chain
                    new_UTO = tmp_UTO

        if new_chain is not None:
            self.chain = new_chain
            self.UTO = new_UTO
            return True

        return False

    @staticmethod
    def check_validity(chain_sample, gen_tx):
        target = "0"*chain_sample.difficulty
        tmp_UTO = dict()
        tmp_UTO[gen_tx.outputs[0].id] = gen_tx.outputs[0]

        for i in range(1, len(chain_sample.chain)):
            curr_block = chain_sample.chain[i]
            prev_block = chain_sample.chain[i - 1]

            if curr_block.hash != curr_block._block_hash():
                print("Hash of block is incorrect")
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
                    if tx_input.output_id not in tmp_UTO:
                        print("Input transaction is missing")
                        return False

                    if tx_input.UTO.value != tmp_UTO[tx_input.output_id].value:
                        print("Invalid input transaction value")
                        return False

                    tmp_UTO.pop(tx_input.output_id)

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

        new_tx = Transaction(self.public_key, recipient, value, inputs)
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

    def __init__(self, sender, recipient, value, inputs):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.inputs = inputs
        self.signature = None
        self.outputs = list()
        self.sequence = 0
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
        self.signature = sk.sign(line)
        return self.signature

    def verify_signature(self):
        line = (self.sender + self.recipient + str(self.value)).encode()
        vk = VerifyingKey.from_pem(self.sender)
        return vk.verify(self.signature, line)

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
        tx_id = self.__calculate_hash()
        self.outputs.append(TransactionOutput(self.recipient, self.value, tx_id))
        self.outputs.append(TransactionOutput(self.sender, left, tx_id))

        for out_tx in self.outputs:
            BlockChain.UTO[out_tx.id] = out_tx

        for tx in self.inputs:
            if tx.UTO is not None:
                BlockChain.UTO.pop(tx.output_id)

        return True


from flask.json import JSONEncoder


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
                'hash': obj.hash,
                'nonce': 0
            }
        if isinstance(obj, Transaction):
            return {
                'sender': obj.sender,
                'recipient': obj.recipient,
                'value': obj.value,
                'inputs': obj.inputs,
                'signature': str(obj.signature),
                'outputs': obj.outputs,
                'sequence': obj.sequence,
                'id': obj.id,
            }
        return super(MyJSONEncoder, self).default(obj)


def main():
    # chain = BlockChain()

    walletA = Wallet()
    walletB = Wallet()
    gen_wallet = Wallet()

    print('Creating genesis transaction')
    gen_tx = Transaction(gen_wallet.public_key, walletA.public_key, 100, None)
    gen_tx.generate_signature(gen_wallet.private_key)
    gen_tx.id = '0'
    gen_tx.outputs.append(TransactionOutput(gen_tx.recipient, gen_tx.value, gen_tx.id))
    BlockChain.UTO[gen_tx.outputs[0].id] = gen_tx.outputs[0]

    print('Creating genesis block')
    gen_block = Block('0')
    gen_block.add_transaction(gen_tx)
    chain.add_to_chain(gen_block)

    print("TEST #1")

    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())
    block1 = Block(gen_block.hash)
    block1.add_transaction(walletA.send_money(walletB.public_key, 40))
    block1.mine_block(chain.difficulty)
    chain.add_to_chain(block1)
    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())

    print("TEST #2")

    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())
    block1 = Block(block1.hash)
    block1.add_transaction(walletA.send_money(walletB.public_key, 400))
    block1.mine_block(chain.difficulty)
    chain.add_to_chain(block1)
    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())

    print("TEST #3")

    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())
    block2 = Block(block1.hash)
    block2.add_transaction(walletB.send_money(walletA.public_key, 40))
    block2.mine_block(chain.difficulty)
    chain.add_to_chain(block2)
    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())

    print(BlockChain.check_validity(chain, gen_tx))


chain = BlockChain()
user_wallet = Wallet()
gen_wallet = Wallet()
gen_tx = None


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
    chain.add_to_chain(gen_block)


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
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
    if BlockChain.check_validity(gen_tx) is True:
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
    last_block = chain.get_last()
    new_block = Block(last_block.hash)

    for tx in chain.waiting_transactions:
        new_block.add_transaction(tx)

    new_block.mine_block(chain.difficulty)

    motive_tx = Transaction(gen_wallet.public_key,
                            user_wallet.public_key, 1, None)
    motive_tx.generate_signature(gen_wallet.private_key)
    motive_tx.outputs.append(TransactionOutput(motive_tx.recipient, motive_tx.value, gen_tx.id))
    BlockChain.UTO[motive_tx.outputs[0].id] = motive_tx.outputs[0]

    # should be a sort of broadcast
    chain.add_to_chain(new_block)
    return "you mined!"


app.json_encoder = MyJSONEncoder

if __name__ == "__main__":
    init()
    app.run(host='0.0.0.0', port=5000)
    # main()
