import os
import math
import argparse
import array

''' Resources used:
    https://www.youtube.com/watch?v=K2Xfm0-owS4
    https://www.youtube.com/watch?v=7uRK9iOk4uk
    https://www.youtube.com/watch?v=dRYHSf5A4lw
    https://www.youtube.com/watch?v=bERjYzLqAfw&t=359s
    https://www.youtube.com/watch?v=4pmR49izUL0
    https://anh.cs.luc.edu/331/code/aes.py
    https://github.com/boppreh/aes/blob/master/aes.py
    https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
    
    Note: There is code from each of these included and modified
    to suit our needs
'''


'''
    AES is a block cipher which encrypts 128 bits (16 bytes) of data at a time. 
    It treats the 16 bytes as a grid of 4x4. 
    Messages which are longer than 128 bits are broken into blocks of 128 bits. 
    Each block is encrypted separately using exactly the same steps. 
    If the message is not divisible by the block length, then padding is appended.
    The stages of the algorithm look this way:
        1. Key Expansion
        2. Initial Round:
            a) AddRoundKey
        3. Rounds:
            a) SubBytes
            b) ShiftRows
            c) MixColumns
            d) AddRoundKey
                Repeat
        4. Final Round:
            a) SubBytes
            b) ShiftRows
            c) AddRoundKey
    More detailed explanation of how each stage works is below
'''
class AES(object):

    # we can have only 2 key sizes, the other ones are not valid
    keySize = dict(SIZE_128=16, SIZE_256=32)

    # Rijndael S-box
    sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

    # Rijndael Inverted S-box
    rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
             0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
             0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
             0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
             0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
             0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
             0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
             0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
             0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
             0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
             0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
             0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
             0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
             0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
             0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
             0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
             0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
             0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
             0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
             0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
             0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
             0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
             0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
             0x21, 0x0c, 0x7d]

    # returns given S-Box Value
    def getSBoxValue(self, num):
        return self.sbox[num]

    # returns given Inverted S-Box Value
    def getSBoxInvert(self, num):
        return self.rsbox[num]

    # Rotates a word eight bits to the left
    # Word is an char list of size 4 (32 bits overall).
    def rotate(self, word):
        return word[1:] + word[:1]

    # Rijndael Rcon
    Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
            0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
            0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
            0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
            0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
            0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
            0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
            0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
            0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
            0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
            0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
            0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
            0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
            0xe8, 0xcb]

    # returns given Rcon Value
    def getRconValue(self, num):
        return self.Rcon[num]



    def core(self, word, iteration):
        # rotate the 32-bit word 8 bits to the left
        word = self.rotate(word)
        # apply S-Box substitution on all 4 parts of the 32-bit word
        for i in range(4):
            word[i] = self.getSBoxValue(word[i])
        # XOR the output of the rcon operation with i to the first part
        # (leftmost) only
        word[0] = word[0] ^ self.getRconValue(iteration)
        return word

    # Each round has its own round key that is derived from the original
    # 128-bit encryption key.
    # One of the four steps of each round, for both encryption and
    # decryption, involves XORing of the round key with the state
    # array.
    def expandKey(self, key, size, expandedKeySize):
        # current expanded keySize, in bytes
        currentSize = 0
        rconIteration = 1
        expandedKey = [0] * expandedKeySize

        # set the 16, 32 bytes of the expanded key to the input key
        for j in range(size):
            expandedKey[j] = key[j]
        currentSize += size

        while currentSize < expandedKeySize:
            # assign the previous 4 bytes to the temporary value t
            t = expandedKey[currentSize - 4:currentSize]

            # every 16,32 bytes we apply the core schedule to t
            # and increment rconIteration afterwards
            if currentSize % size == 0:
                t = self.core(t, rconIteration)
                rconIteration += 1
            # For 256-bit keys, we add an extra sbox to the calculation
            if size == self.keySize["SIZE_256"] and ((currentSize % size) == 16):
                for l in range(4): t[l] = self.getSBoxValue(t[l])

            # We XOR t with the four-byte block 16,32 bytes before the new
            # expanded key.  This becomes the next four bytes in the expanded
            # key.
            for m in range(4):
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ \
                                           t[m]
                currentSize += 1

        return expandedKey

    # State: We can think of a 128-bit block as consisting of a 4 × 4 array of
    # bytes and this array of bytes is referred to as the state

    # The Add Round Key is used in 2 places – the whitening step and in the inner loop.
    # This step involves adding the state and the round key using binary addition mod 2.
    # The state and round key are added as Galois fields.
    # This means that every bit in the input is added to the corresponding bit in the round key
    #  and the result mod 2 is stored in the state.
    def addRoundKey(self, state, roundKey):
        for i in range(16):
            state[i] ^= roundKey[i]
        return state

    # Creates a round key from the given expanded key and
    # the position within the expanded key
    def createRoundKey(self, expandedKey, roundKeyPointer):
        roundKey = [0] * 16
        for i in range(4):
            for j in range(4):
                roundKey[j * 4 + i] = expandedKey[roundKeyPointer + i * 4 + j]
        return roundKey

    # performs Galois multiplication of 8 bit characters
    def galois_multiplication(self, a, b):
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    # In the subBytes step we replace each byte of the state
    # with another byte depending on the key.
    # The substitutions are usually presented as the Look-up table called Rijndael S-box. (The one above)
    def subBytes(self, state, isInv):
        if isInv:
            getter = self.getSBoxInvert
        else:
            getter = self.getSBoxValue
        for i in range(16): state[i] = getter(state[i])
        return state

    # The Shift Rows step shifts the rows of the state to the left.
    # The first row is not shifted. The second row is shifted by 1 byte to the left.
    # The third row is shifted by 2 bytes, and the final row is shifted by 3 bytes.
    # As bytes are shifted out on the left, the reappear on the right. This operation is sometimes called rotation.
    # We do each shift using the shiftRow function below
    def shiftRows(self, state, isInv):
        for i in range(4):
            state = self.shiftRow(state, i * 4, i, isInv)
        return state

    # each iteration shifts the row to the left by 1
    def shiftRow(self, state, statePointer, nbr, isInv):
        for i in range(nbr):
            if isInv:
                state[statePointer:statePointer + 4] = \
                    state[statePointer + 3:statePointer + 4] + \
                    state[statePointer:statePointer + 3]
            else:
                state[statePointer:statePointer + 4] = \
                    state[statePointer + 1:statePointer + 4] + \
                    state[statePointer:statePointer + 1]
        return state

    # This step replaces each byte of a column by a function of all the
    # bytes in the same column:
    # Each byte in a column is replaced by two times
    # that byte, plus three times the the next byte, plus the byte that
    # comes next, plus the byte that follows.
    def mixColumns(self, state, isInv):
        # iterate over the 4 columns
        for i in range(4):
            # construct one column by slicing over the 4 rows
            column = state[i:i + 16:4]
            # apply the mixColumn on one column
            column = self.mixColumn(column, isInv)
            # put the values back into the state
            state[i:i + 16:4] = column

        return state

    # galois multiplication of 1 column of the 4x4 matrix
    def mixColumn(self, column, isInv):
        if isInv:
            mult = [14, 9, 13, 11]
        else:
            mult = [2, 1, 1, 3]
        cpy = list(column)
        g = self.galois_multiplication

        column[0] = g(cpy[0], mult[0]) ^ g(cpy[3], mult[1]) ^ \
                    g(cpy[2], mult[2]) ^ g(cpy[1], mult[3])
        column[1] = g(cpy[1], mult[0]) ^ g(cpy[0], mult[1]) ^ \
                    g(cpy[3], mult[2]) ^ g(cpy[2], mult[3])
        column[2] = g(cpy[2], mult[0]) ^ g(cpy[1], mult[1]) ^ \
                    g(cpy[0], mult[2]) ^ g(cpy[3], mult[3])
        column[3] = g(cpy[3], mult[0]) ^ g(cpy[2], mult[1]) ^ \
                    g(cpy[1], mult[2]) ^ g(cpy[0], mult[3])
        return column

    # applies the 4 operations of the forward round in sequence
    def aesRound(self, state, roundKey):
        state = self.subBytes(state, False)
        state = self.shiftRows(state, False)
        state = self.mixColumns(state, False)
        state = self.addRoundKey(state, roundKey)
        return state

    # applies the 4 operations of the inverse round in sequence
    def aesInvRound(self, state, roundKey):
        state = self.shiftRows(state, True)
        state = self.subBytes(state, True)
        state = self.addRoundKey(state, roundKey)
        state = self.mixColumns(state, True)
        return state

    # Perform:
    # 1.Initial Round:
    #   a)	AddRoundKey
    # 2.Rounds:
    #   a)	SubBytes
    #   b)	ShiftRows
    #   c)	MixColumns
    #   d)	AddRoundKey
    #           Repeat
    # 3.Final Round:
    #   a)	SubBytes
    #   b)	ShiftRows
    #   c)	AddRoundKey
    def aesMain(self, state, expandedKey, nbrRounds):
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        i = 1
        while i < nbrRounds:
            state = self.aesRound(state,
                                  self.createRoundKey(expandedKey, 16 * i))
            i += 1
        state = self.subBytes(state, False)
        state = self.shiftRows(state, False)
        state = self.addRoundKey(state,
                                 self.createRoundKey(expandedKey, 16 * nbrRounds))
        return state

    # Behaves similarly as the one above
    # just uses the inverse functions
    def aesInvMain(self, state, expandedKey, nbrRounds):
        state = self.addRoundKey(state,
                                 self.createRoundKey(expandedKey, 16 * nbrRounds))
        i = nbrRounds - 1
        while i > 0:
            state = self.aesInvRound(state,
                                     self.createRoundKey(expandedKey, 16 * i))
            i -= 1
        state = self.shiftRows(state, True)
        state = self.subBytes(state, True)
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        return state

    # encrypts a 128 bit input block with the given key of a specific size
    def encrypt(self, iput, key, size):
        output = [0] * 16
        # the number of rounds
        nbrRounds = 0
        # the 128 bit block to encode
        block = [0] * 16
        # set the number of rounds
        if size == self.keySize["SIZE_128"]:
            nbrRounds = 10
        elif size == self.keySize["SIZE_256"]:
            nbrRounds = 14
        else:
            return None

        # the expanded keySize
        expandedKeySize = 16 * (nbrRounds + 1)

        # Set the block values, for the block
        # iterate over the columns
        for i in range(4):
            # iterate over the rows
            for j in range(4):
                block[(i + (j * 4))] = iput[(i * 4) + j]

        # expands the key
        expandedKey = self.expandKey(key, size, expandedKeySize)

        # encrypt the block using the expandedKey
        block = self.aesMain(block, expandedKey, nbrRounds)

        # unmap the block again into the output
        for k in range(4):
            # iterate over the rows
            for l in range(4):
                output[(k * 4) + l] = block[(k + (l * 4))]
        return output

    # decrypts a 128 bit input block with the given key of a specific size
    def decrypt(self, iput, key, size):
        output = [0] * 16
        # the number of rounds
        nbrRounds = 0
        # the 128 bit block to decode
        block = [0] * 16
        # set the number of rounds
        if size == self.keySize["SIZE_128"]:
            nbrRounds = 10
        elif size == self.keySize["SIZE_256"]:
            nbrRounds = 14
        else:
            return None

        # the expanded keySize
        expandedKeySize = 16 * (nbrRounds + 1)

        # Set the block values, for the block

        # iterate over the columns
        for i in range(4):
            # iterate over the rows
            for j in range(4):
                block[(i + (j * 4))] = iput[(i * 4) + j]
        # expand the key
        expandedKey = self.expandKey(key, size, expandedKeySize)
        # decrypt the block using the expandedKey
        block = self.aesInvMain(block, expandedKey, nbrRounds)
        # unmap the block again into the output
        for k in range(4):
            # iterate over the rows
            for l in range(4):
                output[(k * 4) + l] = block[(k + (l * 4))]
        return output

    # converts a 16 character string into a number array
    def convertString(self, string, start, end):
        if end - start > 16: end = start + 16
        ar = [0] * 16

        i = start
        j = 0
        while len(ar) < end - start:
            ar.append(0)
        while i < end:
            ar[j] = string[i]
            j += 1
            i += 1
        return ar

    # Note: Initilization Vector is an input that is typically required to be random or pseudorandom

    # Encryption
    # inputString - Input String
    # key - a key of the given size
    # size - length of the key
    # IV - the 128 bit Initilization Vector (random vector)
    def encrypt2(self, inputString, key, size, IV):
        if len(key) % size:
            return None
        if len(IV) % 16:
            return None
        # the AES input/output
        plaintext = []
        iput = [0] * 16
        output = []
        ciphertext = [0] * 16
        # the output cipher string
        cipherOut = []
        firstRound = True
        if inputString != None:
            for j in range(int(math.ceil(float(len(inputString)) / 16))):
                start = j * 16
                end = j * 16 + 16
                if end > len(inputString):
                    end = len(inputString)
                plaintext = self.convertString(inputString, start, end)
                for i in range(16):
                    if firstRound:
                        iput[i] = plaintext[i] ^ IV[i]
                    else:
                        iput[i] = plaintext[i] ^ ciphertext[i]
                firstRound = False
                ciphertext = self.encrypt(iput, key, size)
                # always 16 bytes because of the padding for CBC
                for k in range(16):
                    cipherOut.append(ciphertext[k])
        return len(inputString), cipherOut

    # Decryption
    # inputCipher - Encrypted String
    # originalsize - The unencrypted string length - required for CBC
    # key - a number array of the bit length size
    # size - length of the key
    # IV - the 128 bit number array Initilization Vector
    def decrypt2(self, inputCipher, originalsize, key, size, IV):
        if len(key) % size:
            return None
        if len(IV) % 16:
            return None
        # the AES input/output
        ciphertext = []
        iput = []
        output = []
        plaintext = [0] * 16
        # the output plain text character list
        chrOut = []
        firstRound = True
        if inputCipher != None:
            for j in range(int(math.ceil(float(len(inputCipher)) / 16))):
                start = j * 16
                end = j * 16 + 16
                if j * 16 + 16 > len(inputCipher):
                    end = len(inputCipher)
                ciphertext = inputCipher[start:end]
                output = self.decrypt(ciphertext, key, size)
                for i in range(16):
                    if firstRound:
                        plaintext[i] = IV[i] ^ output[i]
                    else:
                        plaintext[i] = iput[i] ^ output[i]
                firstRound = False
                if originalsize is not None and originalsize < end:
                    for k in range(originalsize - start):
                        chrOut.append(chr(plaintext[k]))
                else:
                    for k in range(end - start):
                        chrOut.append(chr(plaintext[k]))
                iput = ciphertext
        return "".join(chrOut)


    # adds padding to s to make it a multiple of 16-bytes
    def appendPadding(s):
        numpads = 16 - (len(s) % 16)
        return s + numpads * chr(numpads)

    # strips s of the padding added
    def stripPadding(s):
        if len(s) % 16 or not s:
            raise ValueError("String of len %d can't be PCKS7-padded" % len(s))
        numpads = ord(s[-1])
        if numpads > 16:
            raise ValueError("String ending with %r can't be PCKS7-padded" % s[-1])
        return s[:-numpads]

    # performs encryption given the data from the file and a key
    # returned cipher is a string of bytes
    def encryptData(self, key, data):
        key = map(ord, key)
        data = self.appendPadding(data)
        keysize = len(key)
        assert keysize in self.keySize.values(), 'invalid key size: %s' % keysize
        # create a new iv using random data
        iv = [ord(i) for i in os.urandom(16)]
        (length, ciph) = moo.encrypt2(data, key, keysize, iv)
        return ''.join(map(chr, iv)) + ''.join(map(chr, ciph))

    # performs decryption given the data from the file and the corresponding key
    def decryptData(self, key, data):
        key = map(ord, key)
        keysize = len(key)
        assert keysize in self.keySize.values(), 'invalid key size: %s' % keysize
        # iv is first 16 bytes
        iv = map(ord, data[:16])
        data = map(ord, data[16:])
        decr = self.decrypt2(data, None, key, keysize, iv)
        decr = self.stripPadding(decr)
        return decr

if __name__ == "__main__":
    moo = AES()

    # parses inputs
    parser = argparse.ArgumentParser()
    parser.add_argument('keysize')
    parser.add_argument('keyfile')
    parser.add_argument('inputfile')
    parser.add_argument('outputfile')
    parser.add_argument('mode')
    args = parser.parse_args()

    args = vars(args)

    # reads the file containing the key
    # IMPORTANT: keyfile should include a key using the comma separated method:
    # 1,2,3,...,16 for a size of 128
    in_file = open(args.get("keyfile"), "rb")  # opening for [r]eading as [b]inary
    key = in_file.read()  # if you only wanted to read 512 bytes, do .read(512)
    in_file.close()


    key = [int(x) for x in key.decode().split(',')]

    # reads inputfile and takes the bytes
    in_file = open(args.get("inputfile"), "rb")  # opening for [r]eading as [b]inary
    data = in_file.read()  # if you only wanted to read 512 bytes, do .read(512)
    in_file.close()
    iv = ""

    orig_len = len(data)

    # Initialises iv with random numbers
    if args.get("keysize") == '128':
        iv = [103, 35, 148, 239, 76, 213, 47, 118, 255, 222, 123, 176, 106, 134, 98, 92]
    else:
        iv = [103, 35, 148, 239, 76, 213, 47, 118, 255, 222, 123, 176, 106,
              134, 98, 92, 133, 38, 118, 539, 761, 13, 447, 218, 765, 213, 321, 80, 56, 114, 108, 19]
    ciph = b''

    # performs encryption or decryption
    if args.get("mode") == 'encrypt':
        if args.get("keysize") == '128':
            orig_len, ciph = moo.encrypt2(data, key, moo.keySize["SIZE_128"], iv)
        else:
            orig_len, ciph = moo.encrypt2(data, key, moo.keySize["SIZE_256"], iv)
        ciph = array.array('B', ciph).tostring()

    else:
        if args.get("keysize") == '128':
            ciph = moo.decrypt2(data, orig_len, key, moo.keySize["SIZE_128"], iv)
        else:
            ciph = moo.decrypt2(data, orig_len, key, moo.keySize["SIZE_256"], iv)
        ciph = ciph.encode()

    # writes the data to the output file
    out_file = open(args.get('outputfile'), "wb")  # open for [w]riting as [b]inary

    out_file.write(ciph)
    out_file.close()
