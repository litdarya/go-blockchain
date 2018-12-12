import time
import hashlib

from ecdsa import SigningKey
from ecdsa import NIST256p
from ecdsa import VerifyingKey

# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend


class SshPair:

    def __init__(self):
        pass

    @staticmethod
    # TODO: public_exponent and key_size -- fix
    # TODO: save keys somewhere
    def get_public_private():
        # key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
        #
        # public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        #
        # pem_private_key = key.private_bytes(encoding=serialization.Encoding.PEM,
        #                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
        #                                     encryption_algorithm=serialization.NoEncryption())
        #
        # return pem_private_key, public_key
        private_key = SigningKey.generate(curve=NIST256p)
        public_key = private_key.get_verifying_key()

        return private_key, public_key

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

        # self.mine_block(BlockChain.difficulty)

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
    min_input = 0
    difficulty = 0
    UTO = dict()

    def __init__(self, difficulty=2):
        self.chain = list()
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

    def check_validity(self):
        for i in range(len(self.chain) - 1):
            if self.chain[i].hash != self.chain[i + 1]. prev_hash:
                print("Not valid previous hash in block {0}".format(i + 1))
                return False

            if self.chain[i + 1].hash != self.chain[i + 1]._block_hash():
                print("Not valid hash in block {0}".format(i + 1))
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

        line = recipient.to_pem().decode('utf-8') + str(value) + str(parent_transaction_id)
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

    # TODO: remove get hash from Block class
    def __calculate_hash(self):
        self.sequence += 1
        line = self.sender.to_pem().decode('utf-8') + \
            self.recipient.to_pem().decode('utf-8') + \
            str(self.value) + str(self.sequence)

        return Block.get_hash(line)

    # TODO: line to self.data but with inputs
    def generate_signature(self, private_key):
        line = self.sender.to_pem() + self.recipient.to_pem() + bytearray(self.value)
        sk = SigningKey.from_string(private_key.to_string(), curve=NIST256p)
        self.signature = sk.sign(line)
        return self.signature

    def verify_signature(self, public_key):
        line = self.sender.to_pem() + self.recipient.to_pem() + bytearray(self.value)
        vk = VerifyingKey.from_string(public_key.to_string(), curve=NIST256p)
        return vk.verify(self.signature, line)

    def get_tx_value(self):
        res = 0

        for tx in self.inputs:
            if tx.UTO is not None:
                res += tx.UTO.value

        return res

    def process_transaction(self):
        if not self.verify_signature(self.sender):
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

        for o in self.outputs:
            BlockChain.UTO[o.id] = o

        for tx in self.inputs:
            if tx.UTO is not None:
                BlockChain.UTO.pop(tx.output_id)

        return True


def main():
    # print("TEST #1")
    # # initial block
    # block = Block('test', '0')
    # chain = BlockChain(4)
    #
    # chain.add_to_chain(block)
    # chain.add_to_chain(Block('test1', str(chain.get_last().hash)))
    # chain.add_to_chain(Block('test2', str(chain.get_last().hash)))
    #
    # chain.print_chain()
    # print(chain.check_validity())
    #
    # print("TEST #2")
    # # wallets testing
    # wallet1 = Wallet()
    # wallet2 = Wallet()
    #
    # print(wallet1.public_key, '\n', wallet1.private_key)
    # print(wallet2.public_key, '\n', wallet2.private_key)
    #
    # transaction = Transaction(wallet1.public_key, wallet2.public_key, 5, None)
    # transaction.generate_signature(wallet1.private_key)
    # print(transaction.verify_signature(wallet1.public_key))

    chain = BlockChain()

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
    chain.add_to_chain(block1)
    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())

    print("TEST #2")

    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())
    block1 = Block(gen_block.hash)
    block1.add_transaction(walletA.send_money(walletB.public_key, 400))
    chain.add_to_chain(block1)
    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())

    print("TEST #3")

    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())
    block2 = Block(gen_block.hash)
    block2.add_transaction(walletB.send_money(walletA.public_key, 40))
    chain.add_to_chain(block2)
    print("A balance: ", walletA.get_balance())
    print("B balance: ", walletB.get_balance())


if __name__ == "__main__":
    main()
