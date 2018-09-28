from concurrent.futures.thread import ThreadPoolExecutor
import os


class AES():

    def __init__(self, plaintextFile, cyphertextFile,
                 keyFile, keyLength):
        self.plaintextFile = plaintextFile
        self.cyphertextFile = cyphertextFile
        self.keyFile = keyFile
        self.key = AES.Key(keyFile, keyLength)

    def __str__(self):
        result = 'Plaintext: \"%s\" ' % self.plaintextFile
        result += 'Cyphertext: \"%s\" ' % self.cyphertextFile
        result += 'Key: \"%s\"' % self.keyFile
        return result

    def encrypt(self):
        print()

    def decrypt(self):
        print()

    def determineRounds(keyLength):
        if(keyLength == 128):
            rounds = 10
        elif(keyLength == 256):
            rounds = 14
        else:
            sys.exit('Unsupported key length.')
        return rounds

    def formatByte(byte):
        return "0x%02X " % byte

    def generateKeyfile(filename, keyLength):
        with open(filename, 'wb') as f:
            if(keyLength == 128):
                numBytes = 16
            elif(keyLength == 256):
                numBytes = 32
            else:
                sys.exit('Unsupported keylength.')
            for i in range(numBytes):
                key = os.urandom(1)
                f.write(key)
        return filename

    class Block():

        NUM_ROWS = 4
        NUM_COLS = 4

        def __init__(self, openedFile):
            self.currentRow = 0
            self.currentCol = 0
            self.state = []
            for r in range(AES.Block.NUM_ROWS):
                self.state.append([])
                for c in range(AES.Block.NUM_COLS):
                    self.state[r].append(0x00)
            if(openedFile is not None):
                for i in range(AES.Block.NUM_ROWS * AES.Block.NUM_COLS):
                    self.setNext(ord(openedFile.read(1)))
                self.resetPointer()

        def __str__(self):
            result = ''
            for r in range(AES.Block.NUM_ROWS):
                for c in range(AES.Block.NUM_COLS):
                    result += AES.formatByte(self.state[r][c])
                result += '\n'
            return result

        def getColumn(self, index):
            return AES.Block.Column(self.state, index)

        def setColumn(self, index, word):
            for r in range(AES.Block.NUM_ROWS):
                self.state[r][index] = word.data[r]

        def getRow(self, index):
            return AES.Block.Row(self.state, index)

        def setRow(self, index, row):
            for c in range(AES.Block.NUM_COLS):
                self.state[index][c] = row.data[c]

        def getNext(self):
            row = self.currentRow
            col = self.currentCol
            if(row == -1 and col == -1):
                return None
            result = self.state[row][col]
            if(row == AES.Block.NUM_ROWS - 1):
                if(col == AES.Block.NUM_COLS - 1):
                    row = -1
                    col = -1
                else:
                    row = 0
                    col += 1
            else:
                row += 1
            self.currentRow = row
            self.currentCol = col
            return result

        def setNext(self, value):
            row = self.currentRow
            col = self.currentCol
            if(row == -1 and col == -1):
                return None
            self.state[row][col] = value
            if(row == AES.Block.NUM_ROWS - 1):
                if(col == AES.Block.NUM_COLS - 1):
                    row = -1
                    col = -1
                else:
                    row = 0
                    col += 1
            else:
                row += 1
            self.currentRow = row
            self.currentCol = col

        def resetPointer(self):
            self.currentRow = 0
            self.currentCol = 0

        class Column():

            def __init__(self, state, index):
                self.data = []
                for r in range(AES.Block.NUM_ROWS):
                    self.data.append(state[r][index])

            def __str__(self):
                result = ''
                for r in range(AES.Block.NUM_ROWS):
                    result += '0x%02X\n' % self.data[r]
                return result

            def rotate(self, n):
                for i in range(n):
                    temp = self.data.pop(0)
                    self.data.append(temp)

        class Row():

            def __init__(self, state, index):
                self.data = []
                for c in range(AES.Block.NUM_COLS):
                    self.data.append(state[index][c])

            def __str__(self):
                result = ''
                for c in range(AES.Block.NUM_COLS):
                    result += AES.formatByte(self.data[c])
                return result

            def rotate(self, n):
                for i in range(n):
                    temp = self.data.pop(0)
                    self.data.append(temp)

    class Key():

        def __init__(self, keyFile, keyLength):
            self.rounds = AES.determineRounds(keyLength)
            self.keyLength = keyLength
            self.roundKeys = []
            with open(keyFile, 'rb') as f:
                self.roundKeys.append(AES.Block(f))
                if(keyLength == 256):
                    self.roundKeys.append(AES.Block(f))
                for r in range(self.rounds):
                    self.roundKeys.append(AES.Block(None))
                    if(keyLength == 256):
                        self.roundKeys.append(AES.Block(None))

        def __str__(self):
            result = ''
            numCols = (AES.Block.NUM_COLS * 4) + AES.Block.NUM_COLS - 1
            result = AES.Key.concatRowDelimiter(result, '=')
            result += '[BEGIN KEY]\n'
            result = AES.Key.concatRowDelimiter(result, '=')
            result = AES.Key.concatRowDelimiter(result, '-')
            for block in self.roundKeys:
                result += str(block)
                result = AES.Key.concatRowDelimiter(result, '-')
            result = AES.Key.concatRowDelimiter(result, '=')
            result += '[END KEY]\n'
            result = AES.Key.concatRowDelimiter(result, '=')
            return result

        def concatRowDelimiter(str, char):
            numCols = (AES.Block.NUM_COLS * 4) + AES.Block.NUM_COLS - 1
            for c in range(numCols):
                str += char
            str += '\n'
            return str

        def getRound(self, index):
            return self.roundKeys[index]


def main():
    keyFile = AES.generateKeyfile('key_test.key', 128)
    key = AES.Key(keyFile, 128)
    print(key)
    instance = AES('plain_test.txt', 'cypher_test.aes', keyFile, 128)
    print(instance)

if __name__ == '__main__':
    main()

    # RCON = [0x01, 0x02, 0x04, 0x08, 0x10, ]
    # #SUB_BYTES

    # # Create a queue of threads that are working on

    # def __init__(self, plainFile, cypherFile, keyFile, keyLength, mode):
    #     self.rounds = determineRounds(keyLength)
    #     self.currentState = 1
    #     self.plainFile = plainFile
    #     self.cypherFile = cypherFile
    #     self.keyFile = keyFile
    #     self.keyLength = keyLength
    #     self.mode = mode

    # def encrypt(self): # INCREASE MAX_WORKERS WHEN DONE DEBUGGING!!!!!!!!
    #     self.key = generateKey();
    #     with ThreadPoolExecutor(max_workers=1) as executor:
    #         with open(self.plainFile, "rb") as f:
    #             stateID = 0
    #             while f.read(1):
    #                 f.seek(-1, 1)
    #                 newState = buildState(f)
    #                 stateID += 1
    #                 executor.submit(encryptState, newState, stateID)

    # def buildState(self, openFile):
    #     paddedZeros = 0
    #     state = [[0 for x in range(AES.NUM_COLS)]
    #             for y in range(AES.NUM_ROWS)]
    #     for c in range(AES.NUM_COLS):
    #         for r in range (AES.NUM_ROWS):
    #             if not (c == AES.NUM_COLS and r == AES.NUM_ROWS):
    #                 byte = openFile.read(1)
    #                 if(byte):
    #                     state[r][c] = byte
    #                 else:
    #                     state[r][c] = 0
    #                     paddedZeros += 1
    #             else:
    #                 state[r][c] = paddedZeros
    #     return state

    # def encryptState(self, state, stateID):
    #     for roundNum in range(self.rounds):
    #         subBytes(state)
    #         shiftRows(state)
    #         mixColumns(state)
    #         #AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])

    # def generateKey(self):
    #     originalKey = [[0 for x in range(AES.NUM_COLS)]
    #                   for y in range(AES.NUM_ROWS)]
    #     for c in range(AES.NUM_COLS):
    #         for r in range (AES.NUM_ROWS):
    #             originalKey[r][c] = os.urandom(1)
    #     self.roundKeys = [originalKey]
    #     previousRoundKey = originalKey
    #     for i in range(self.rounds):
    #         newRoundKey = [[0 for x in range(AES.NUM_COLS)]
    #                       for y in range(AES.NUM_ROWS)]
    #         rotWord = []
    #         for x in range(AES.NUM_ROWS):
    #             rotWord.append(previousRoundKey[x][3])
    #         temp = rotWord[0]
    #         rotWord[0] = rotWord[AES.NUM_ROWS - 1]
    #         rotWord[AES.NUM_ROWS - 1] = temp
