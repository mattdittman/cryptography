import binascii
import base64
import codecs
from itertools import combinations

def GetCharacterScore(a, c):
    targetStringChars = list(a)
    total = 0
    for x in targetStringChars:
        if x == c:
            total += 1
    return total


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