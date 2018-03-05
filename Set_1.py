import codecs
import base64
import crypto

def Challenge_1(hexVal):
    return base64.b64encode(codecs.decode(hexVal, "hex")).decode('utf8')

def Challenge_2(a, b):
    b1 = bytearray(codecs.decode(a, 'hex'))
    b2 = bytearray(codecs.decode(b, 'hex'))
    b = bytes([x ^ y for x, y in zip(b1, b2)])
    return codecs.encode(b, "hex").decode('utf8')

def Challenge_3(a):
    topLikelyKey = crypto.GetPhraseScore(a)
    hexVal = codecs.decode(a, 'hex')
    return ''.join(chr(b ^ topLikelyKey["topKey"]) for b in hexVal)

def Challenge_4(fname):
    bestKey = ""
    maxVal = 0
    bestLine = ""
    with open(fname) as f:
        content = f.readlines()
        content = [x.strip() for x in content] 
    for line in content:
        r = crypto.GetPhraseScore(line)
        if r["maxScore"] > maxVal:
            maxVal = r["maxScore"]
            bestLine = line
            bestKey = r["topKey"]    
    hexVal = codecs.decode(bestLine, 'hex')            
    return ''.join(chr(b ^ bestKey) for b in hexVal).strip()

def Challenge_5(encryptLines, key):
    result = []
    for line in encryptLines:
        r = crypto.GetRepeatingKeyXor(key, line)      
        result.append(r)  
    return result

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

#Detect single-character XOR
#c4_answer = Challenge_4("Challenge4.txt")
#assert c4_answer == "Now that the party is jumping"
#print("Challenge 4 Pass")

#Implement repeating-key XOR
c5_answer = Challenge_5(["Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"], "ICE")
assert c5_answer[0] == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
print("Challenge 5 Pass")

c6_answer1 = crypto.GetHammingDistance(b"this is a test", b"wokka wokka!!!")
assert c6_answer1 == 37