import codecs
import base64
import binascii

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

def Challenge_1(hexVal):
    return base64.b64encode(codecs.decode(hexVal, "hex")).decode('utf8')

def Challenge_2(a, b):
    b1 = bytearray(codecs.decode(a, 'hex'))
    b2 = bytearray(codecs.decode(b, 'hex'))
    b = bytes([x ^ y for x, y in zip(b1, b2)])
    return codecs.encode(b, "hex").decode('utf8')

def Challenge_3(a):
    hexVal = codecs.decode(a, 'hex')
    topKey = ""
    maxScore = 0
    for xor_key in range(256):
        decoded = ''.join(chr(b ^ xor_key) for b in hexVal)
        score = GetFrequencyScore(decoded.upper())
        if score > maxScore:
            maxScore = score
            topKey = xor_key
    return ''.join(chr(b ^ topKey) for b in hexVal)

#Convert Hex to Base64
c1_answer = Challenge_1("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
assert c1_answer == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
print("Challenge 1 Pass")

#Fixed XOR
c2_answer = Challenge_2("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
assert c2_answer == "746865206b696420646f6e277420706c6179"
print("Challenge 2 Pass")

#Single-byte XOR Cipher
c3_answer = Challenge_3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
assert c3_answer == "Cooking MC's like a pound of bacon"
print("Challenge 3 Pass")