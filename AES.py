from concurrent.futures.thread import ThreadPoolExecutor
import os


class AES():

    S_BOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
             0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
             0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
             0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
             0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
             0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
             0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
             0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
             0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
             0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
             0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
             0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
             0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
             0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
             0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
             0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

    R_CON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

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

    @staticmethod
    def determineRounds(keyLength):
        if(keyLength == 128):
            rounds = 10
        elif(keyLength == 256):
            rounds = 14
        else:
            sys.exit('Unsupported key length.')
        return rounds

    @staticmethod
    def formatByte(byte):
        return "0x%02X " % byte

    @staticmethod
    def substituteByte(byte):
        return AES.S_BOX[byte]

    def substituteWord(word):
        for i in range(AES.Block.NUM_ROWS):
            byte = word.data[i]
            word.data[i] = AES.substituteByte(byte)
        return word

    @staticmethod
    def generateKeyfile(filename, values, keyLength):
        with open(filename, 'wb') as f:
            if(keyLength == 128):
                numBytes = 16
            elif(keyLength == 256):
                numBytes = 32
            else:
                sys.exit('Unsupported keylength.')
            if(values is not None):
                index = 0
                while index < len(values):
                    val1 = values[index] << 8
                    val2 = values[index + 1]
                    key = (val1 + val2).to_bytes(2, byteorder='big')
                    f.write(key)
                    index += 2
            else:
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
            self.numRounds = AES.determineRounds(keyLength)
            self.keyLength = keyLength
            self.rounds = []
            mult = 1
            with open(keyFile, 'rb') as f:
                self.rounds.append(AES.Block(f))
                if(keyLength == 256):
                    self.rounds.append(AES.Block(f))
                    mult = 2
            previousWord = self.rounds[len(self.rounds) - 1].getColumn(
                AES.Block.NUM_COLS - 1)
            wordNum = len(self.rounds) * AES.Block.NUM_COLS
            nk = wordNum
            for roundIndex in range(len(self.rounds), self.numRounds + 1):
                self.rounds.append(AES.Block(None))
                for columnIndex in range(AES.Block.NUM_COLS):
                    currentWord = previousWord
                    if(wordNum % nk == 0):
                        currentWord.rotate(1)
                    if(wordNum % AES.Block.NUM_COLS == 0):
                        AES.substituteWord(currentWord)
                    if(wordNum % nk == 0):
                        rconVal = AES.R_CON[int(wordNum/nk)]
                        currentWord.data[0] = currentWord.data[0] ^ rconVal
                    trailingWord = self.rounds[roundIndex - mult].getColumn(
                        columnIndex)
                    for i in range(AES.Block.NUM_ROWS):
                        currentWord.data[i] = currentWord.data[i] ^ trailingWord.data[i]
                    self.rounds[roundIndex].setColumn(columnIndex, currentWord)
                    previousWord = currentWord
                    wordNum += 1

        def __str__(self):
            result = ''
            numCols = (AES.Block.NUM_COLS * 4) + AES.Block.NUM_COLS - 1
            result = AES.Key.concatRowDelimiter(result, '=')
            result += '[BEGIN KEY]\n'
            result = AES.Key.concatRowDelimiter(result, '=')
            result = AES.Key.concatRowDelimiter(result, '-')
            for keyRound in self.rounds:
                result += str(keyRound)
                result = AES.Key.concatRowDelimiter(result, '-')
            result = AES.Key.concatRowDelimiter(result, '=')
            result += '[END KEY]\n'
            result = AES.Key.concatRowDelimiter(result, '=')
            return result

        @staticmethod
        def concatRowDelimiter(str, char):
            numCols = (AES.Block.NUM_COLS * 4) + AES.Block.NUM_COLS - 1
            for c in range(numCols):
                str += char
            str += '\n'
            return str

        def getRound(self, index):
            return self.roundKeys[index]


def main():
    values_128 = [0x2b, 0x7e, 0x15, 0x16,
                  0x28, 0xae, 0xd2, 0xa6,
                  0xab, 0xf7, 0x15, 0x88,
                  0x09, 0xcf, 0x4f, 0x3c]

    values_256 = [0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x01]
    values = values_128
    keySize = len(values) * 8
    keyFile = AES.generateKeyfile('key_test.key', values, keySize)
    plainFile = 'plain_test.txt'
    cypherFile = 'cypher_test.aes'
    instance = AES(plainFile, cypherFile, keyFile, keySize)
    print(instance)
    print(instance.key)

if __name__ == '__main__':
    main()
