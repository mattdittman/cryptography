import crypto
import base64

#Implement PKCS#7 padding
def Challenge_9(byteVal, length):
    return crypto.PKCS7_pad(byteVal, length)

#Implement CBC mode
def Challenge_10(key, iv, textFile):
    ciphertext = base64.b64decode(open(textFile, 'r').read())
    result = crypto.AES_128_Decipher_ECB(key, iv, ciphertext)
    return result[:100]

#An ECB/CBC detection oracle
def Challenge_11(text):
    appendedText = text + b"********************************************************************************************"
    encrypted = crypto.Encryption_Oracle(appendedText, None)
    is_EBC = crypto.Detect_ECB_Encryption(encrypted["EncryptedVal"])
    mode = 'CBC'        
    if is_EBC == True:
        mode = "ECB"
    return {"Mode" : encrypted["Mode"], "DetectedMode" : mode }

#Implement PKCS#7 padding
c9_answer = Challenge_9(b"YELLOW SUBMARINE", 20)
assert c9_answer == b'YELLOW SUBMARINE\x04\x04\x04\x04'
print("Challenge 9 Pass")

#Implement CBC mode
c10_answer = Challenge_10(b"YELLOW SUBMARINE", b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', "Challenge10.txt")
assert c10_answer == b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the"
print("Challenge 10 Pass")

#An ECB/CBC detection oracle
i = 0
while i < 100:
    c11_answer = Challenge_11(b"Hey, you jive turkey")
    assert c11_answer["Mode"] == c11_answer["DetectedMode"]
    c11_answer = Challenge_11(b"Catch you on the flip side")
    assert c11_answer["Mode"] == c11_answer["DetectedMode"]
    c11_answer = Challenge_11(b"Up your nose with a rubber hose")
    assert c11_answer["Mode"] == c11_answer["DetectedMode"]
    c11_answer = Challenge_11(b"Stop dipping in my Kool-Aid")
    assert c11_answer["Mode"] == c11_answer["DetectedMode"]
    c11_answer = Challenge_11(b"Sit on it")
    assert c11_answer["Mode"] == c11_answer["DetectedMode"]
    i += 1
print("Challenge 11 Pass")

#Byte-at-a-time ECB decryption (Simple)
crypto.Byte_At_A_Time_Encryption_Oracle(b'Fourscore and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal. ')