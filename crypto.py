import binascii
import base64
import codecs
from itertools import combinations
from Cryptodome.Cipher import AES
from os import urandom
from random import SystemRandom
from random import randint

def GetCharacterScore(a, c):
    targetStringChars = list(a)
    total = 0
    for x in targetStringChars:
        if x == c:
            total += 1
    return total

def Detect_ECB_Encryption(content):
    repeats = 0
    chunks = DivideIntoChunks(content, 16, 0)
    for c in chunks:
        if chunks.count(c) > 1:
            #more than one occurance of 16 byte segment; probably ECB
            repeats += 1
    if repeats > 0:
        return True
    return False

def GetFrequencyScore(a):
    frequent_Chars = list("ETAOIN SHRDLU")
    total = 0
    for x in frequent_Chars:
        total += GetCharacterScore(a, x)
    return total

def GetSingleByteXorAndScore(bytesVal):
    topKey = ""
    maxScore = 0    
    for xor_key in range(256):
        decoded = ''.join(chr(b ^ xor_key) for b in bytesVal)
        score = GetFrequencyScore(decoded.upper())
        if score > maxScore:
            maxScore = score
            topKey = xor_key
    return {"topKey":topKey, "maxScore": maxScore}

def GetSingleByteXor(bytesVal):
    return GetSingleByteXorAndScore(bytesVal)["topKey"]    

def FixedXorFromHex(a, b):
    b1 = bytearray(codecs.decode(a, 'hex'))
    b2 = bytearray(codecs.decode(b, 'hex'))
    return FixedXorFromBytearrays(b1, b2)

def FixedXorFromBytearrays(b1, b2):
    b = bytes([x ^ y for x, y in zip(b1, b2)])
    return b   

def DecryptFixedXor(key, text):
    keyBuffer = ExpandKeyBufferToText(key, text)
    if (len(keyBuffer) != len(text)):
        raise ValueError('Buffer length mismatch')

    output = b''

    for x, y in zip(keyBuffer, text):
        output += bytes([x ^ y])

    return output   

def ExpandKeyBufferToText(key, text):
    keyLength = len(key)
    textLength  = len(text)
    k = key * (textLength // keyLength)
    if len(k) < textLength:
        rem = textLength % keyLength
        k += key[:rem]
    return k

def GetRepeatingKeyXor(key, text):
    k = ExpandKeyBufferToText(key, text)
    keyList = list(map(ord, k))
    stringList = list(map(ord, text))
    encrypted =  []
    for i, x in enumerate(stringList):
        val = "{:02x}".format(keyList[i]^x)
        encrypted.append(val)
    retVal = ''.join(encrypted)
    return retVal

def GetHammingDistance(val1, val2):
    if len(val1) != len(val2):
        return -1    
    z = list(zip(val1, val2))
    dist = 0
    for bit1, bit2 in z:
        diff = bit1 ^ bit2
        binDiff = bin(diff)
        for b in binDiff:
            if b == '1':
                dist += 1
        #dist += sum([1 for bit in bin(diff) if bit == '1'])
    return dist

def GetBase64DecodedFileContents(textFile):
    with open(textFile, 'rb') as f:
        rawdata = f.read()
    return base64.b64decode(rawdata)

def GetAverageHammingDistance(contents, chunkSize, chunkCount):
    chunks = DivideIntoChunks(contents, chunkSize, chunkCount)
    total_score = 0
    for (x, y) in combinations(chunks, 2):
        total_score += GetHammingDistance(x, y)
    normalized_score = total_score / chunkSize
    return normalized_score 

def DivideIntoChunks(contents, chunkSize, chunkCount):
    currentChunkIndex = 0
    results = []
    while currentChunkIndex < len(contents):
        results.append(contents[currentChunkIndex:currentChunkIndex + chunkSize])
        currentChunkIndex += chunkSize
    if  chunkCount > 0:
        return results[:chunkCount]
    return results

def TransposeChunks(chunks):
    maxChunkLength = len(chunks[0])
    result = []
    for idx in range(0, maxChunkLength):
        obj = b''
        for chunk in chunks:
            try:
                obj += bytes([chunk[idx]])
            except IndexError:
                break
        result.append(obj)
    return result

#Depad PKCS7 bytestring
def PKCS7_depad(bytestring, k=16):
    val = bytestring[-1]
    if val > k:
        raise ValueError('Input is not padded or padding is corrupt')
    l = len(bytestring) - val
    return bytestring[:l]


#Pad bytestring according to PKCS7
def PKCS7_pad(bytestring, k=16):
    l = len(bytestring)
    val = k - (l % k)
    return bytestring + bytearray([val] * val)

def AES_128_Decipher_ECB(key, iv, byteVal):
    chunks = DivideIntoChunks(byteVal, 16, 0)
    cipher = AES.new(key, AES.MODE_ECB)
    result = b""
    for chunk in chunks:
        decrypted = cipher.decrypt(chunk)
        s = DecryptFixedXor(decrypted, iv)
        result += s
        iv = chunk
    return result


def AES_128_Encrypt_CBC(text, iv = None, key = None):
    if iv == None:
        iv = urandom(16)
    if key == None:
        key = urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b''
    diffblock = iv
    stringToEncrypt = PKCS7_pad(text, 16)
    for plaintext_chunk in DivideIntoChunks(stringToEncrypt, 16, 0):
        xor_bytes = FixedXorFromBytearrays(plaintext_chunk, diffblock)
        current_ciphertext_chunk = cipher.encrypt(xor_bytes)
        ciphertext += current_ciphertext_chunk
        diffblock = current_ciphertext_chunk
    return ciphertext    

def EncryptECB(str, key = None):
    if key == None:
        key = urandom(16)
    stringToEncrypt = PKCS7_pad(str, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    stringToEncrypt = PKCS7_pad(stringToEncrypt, 16)
    encryptedVal = cipher.encrypt(stringToEncrypt)
    return cipher.encrypt(stringToEncrypt)


def Encryption_Oracle(input, specifiedMode = "ECB", key = None):
    tagLength = randint(5,10)
    prefix = urandom(tagLength)
    suffix = urandom(tagLength)
    stringToEncrypt = prefix + input + suffix
    thisMode = specifiedMode
    if specifiedMode == None:
        encryptionModes = ['ECB', 'CBC']
        thisMode = SystemRandom().choice(encryptionModes) 
    encryptedVal = b""
    if thisMode == 'CBC':        
        encryptedVal = AES_128_Encrypt_CBC(stringToEncrypt)
    else:
        encryptedVal = EncryptECB(stringToEncrypt, key)
    return {"Mode" : thisMode, "EncryptedVal" : ''.join('{:02x}'.format(x) for x in encryptedVal)}

def BlocksizeFinder():
    seed = b'A'
    encryptedLength = len(EncryptECB(seed))
    i = 0
    while i <= encryptedLength:
        seed += b"A"
        i = len(EncryptECB(seed))
    return i - encryptedLength

def BuildEncryptionDictionary(blocksize, key):
    inputBlock = b"A" * blocksize 
    i = 1
    dictionary = []
    while i < 256:
        thisChar = inputBlock + bytes([i])
        cipher = EncryptECB(thisChar, key)
        #This pads out 16 extra spaces
        #the byte at position 16 is the value we need

        dictionary.append({"id": i, "cipher": cipher})
        i += 1

    x = 1

def Byte_At_A_Time_Encryption_Oracle(input):
    key = b"Boom ChackaLacka"
    addString = (b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                 b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                 b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                 b"YnkK")
    workingString = input + base64.b64decode(addString)
    encrypted = EncryptECB(workingString, key)
    blocksize = BlocksizeFinder()
    BuildEncryptionDictionary(blocksize, key)
