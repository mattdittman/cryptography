import codecs
import base64
import crypto
from Cryptodome.Cipher import AES

#Convert Hex to Base64
def Challenge_1(hexVal):
    return base64.b64encode(codecs.decode(hexVal, "hex")).decode('utf8')

#Fixed XOR
def Challenge_2(a, b):
    b1 = bytearray(codecs.decode(a, 'hex'))
    b2 = bytearray(codecs.decode(b, 'hex'))
    b = bytes([x ^ y for x, y in zip(b1, b2)])
    return codecs.encode(b, "hex").decode('utf8')

#Single-byte XOR Cipher
def Challenge_3(hexString):
    bytesVal = codecs.decode(hexString, 'hex')
    topLikelyKey = crypto.GetSingleByteXor(bytesVal)
    return ''.join(chr(b ^ topLikelyKey) for b in bytesVal)

#Detect single-character XOR (takes a long time)
def Challenge_4(fname):
    bestKey = ""
    maxVal = 0
    bestLine = ""
    with open(fname) as f:
        content = f.readlines()
        content = [x.strip() for x in content] 
    for line in content:
        bytesVal = codecs.decode(line, 'hex')
        r = crypto.GetSingleByteXorAndScore(bytesVal)
        if r["maxScore"] > maxVal:
            maxVal = r["maxScore"]
            bestLine = line
            bestKey = r["topKey"]    
    bestLineBytes = codecs.decode(bestLine, 'hex')            
    return ''.join(chr(b ^ bestKey) for b in bestLineBytes).strip()

#Implement repeating-key XOR 
def Challenge_5(encryptLines, key):
    result = []
    for line in encryptLines:
        r = crypto.GetRepeatingKeyXor(key, line)      
        result.append(r)  
    return result

#Break repeating-key XOR
def Challenge_6(textFile):
    assert crypto.GetHammingDistance(b"this is a test", b"wokka wokka!!!") == 37
    leastDistance = (-1, -1)
    base64FileContents = crypto.GetBase64DecodedFileContents(textFile)
    for i in range(2, 41):
        average = crypto.GetAverageHammingDistance(base64FileContents, i, 4)
        if leastDistance[0] == -1 or average < leastDistance[1]:
            leastDistance = (i, average)            
    
    fileChunks = crypto.DivideIntoChunks(base64FileContents, leastDistance[0], 0)
    transposed = crypto.TransposeChunks(fileChunks)
    
    key = ''
    for a in transposed:
        r = crypto.GetSingleByteXorAndScore(a)
        key += chr(r["topKey"])
    val = crypto.DecryptFixedXor(key.encode('utf-8'), base64FileContents)
    return val[:100]

#AES in ECB mode
def Challenge_7(textFile, keyStr):
    base64FileContents = crypto.GetBase64DecodedFileContents(textFile)
    cipher = AES.new(keyStr, AES.MODE_ECB)
    result = cipher.decrypt(base64FileContents)
    return result[:100]

#Detect AES in ECB mode
def Challenge_8(textFile):
    results = []
    with open(textFile) as f:
        content = f.readlines() 
    content = [x.strip() for x in content]
    for line in content:
        repeats = 0
        chunks = crypto.DivideIntoChunks(line, 16, 0)
        for c in chunks:
            if chunks.count(c) > 1:
                #more than one occurance of 16 byte segment; probably ECB
                repeats += 1
        if repeats > 0:
            results.append(line)
    assert len(results) == 1
    return results[0]

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

#Detect single-character XOR (takes a long time)
c4_answer = Challenge_4("Challenge4.txt")
assert c4_answer == "Now that the party is jumping"
print("Challenge 4 Pass")

#Implement repeating-key XOR
c5_answer = Challenge_5(["Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"], "ICE")
assert c5_answer[0] == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
print("Challenge 5 Pass")

#Break repeating-key XOR
c6_answer = Challenge_6("Challenge6.txt")
assert c6_answer == b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the"
print("Challenge 6 Pass")

#AES in ECB mode
c7_answer = Challenge_7("Challenge7.txt", b"YELLOW SUBMARINE")
assert c7_answer == b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the"
print("Challenge 7 Pass")

#Detect AES in ECB mode
c8_answer = Challenge_8("Challenge8.txt")
assert c8_answer == "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
print("Challenge 8 Pass")