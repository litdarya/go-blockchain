import time
import hashlib


class ProofOfWeight:
    pass


class Block:
    # timestamp
    # hash
    # previous hash
    # message
    # nonce

    def __init__(self, message, prev_hash):
        self.message = message
        self.prev_hash = prev_hash
        self.timestamp = time.time()

        self.__nonce = 0
        self.hash = self._block_hash()

        self.mine_block(BlockChain.difficulty)

    def _block_hash(self):
        line = self.prev_hash + str(self.timestamp) + str(self.__nonce) + self.message
        return Block.__get_hash(line)

    @staticmethod
    def __get_hash(line):
        res = hashlib.sha256()
        res.update(line.encode('utf-8'))
        return res.hexdigest()

    def print_block(self):
        print("Message: {0}\nTimestamp: {1}\nHash: {2}".format(self.message, self.timestamp, self.hash))

    def mine_block(self, difficulty):
        target = "0"*difficulty
        tmp_hash = self.hash

        while tmp_hash[:difficulty] != target:
            self.__nonce += 1
            tmp_hash = self._block_hash()

        self.hash = tmp_hash
        print("Successfully mined {0}".format(tmp_hash))


class BlockChain:
    # chain = list()
    difficulty = 0

    def __init__(self, difficulty=2):
        self.chain = list()
        BlockChain.difficulty = difficulty

    def add_to_chain(self, block):
        self.chain.append(block)

    # maybe print to json?
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

    def __init__(self):
        pass

    def __generate_key_pair(self):
        pass

def main():
    # initial block
    block = Block('test', '0')
    chain = BlockChain(4)

    chain.add_to_chain(block)
    chain.add_to_chain(Block('test1', str(chain.get_last().hash)))
    chain.add_to_chain(Block('test2', str(chain.get_last().hash)))

    chain.print_chain()
    print(chain.check_validity())


if __name__ == "__main__":
    main()
