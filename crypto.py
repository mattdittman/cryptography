import binascii
import codecs

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

def GetPhraseScore(a):
    hexVal = codecs.decode(a, 'hex')
    topKey = ""
    maxScore = 0    
    for xor_key in range(256):
        decoded = ''.join(chr(b ^ xor_key) for b in hexVal)
        score = GetFrequencyScore(decoded.upper())
        if score > maxScore:
            maxScore = score
            topKey = xor_key
    return {"topKey":topKey, "maxScore": maxScore}

def GetRepeatingKeyXor(key, text):
    keyLength = len(key)
    textLength  = len(text)
    k = key * (textLength // keyLength)
    if len(k) < textLength:
        rem = textLength % keyLength
        k += key[:rem]
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