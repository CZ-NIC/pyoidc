#!/usr/bin/env python


# Code taken from iphone-dataprotection (BSD License)
# http://code.google.com/p/iphone-dataprotection/source/browse/python_scripts/crypto/gcm.py


from Crypto.Cipher import AES
from Crypto.Util import strxor
from struct import pack, unpack

def gcm_rightshift(vec):
    for x in range(15, 0, -1):
        c = vec[x] >> 1
        c |= (vec[x-1] << 7) & 0x80
        vec[x] = c
    vec[0] >>= 1
    return vec

def gcm_gf_mult(a, b):
    mask = [ 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 ]
    poly = [ 0x00, 0xe1 ]

    Z = [0] * 16
    V = [c for c in a]

    for x in range(128):
        if b[x >> 3] & mask[x & 7]:
            Z = [V[y] ^ Z[y] for y in range(16)]
        bit = V[15] & 1
        V = gcm_rightshift(V)
        V[0] ^= poly[bit]
    return Z

def ghash(h, auth_data, data):
    u = (16 - len(data)) % 16
    v = (16 - len(auth_data)) % 16

    x = auth_data + chr(0) * v + data + chr(0) * u
    x += pack('>QQ', len(auth_data) * 8, len(data) * 8)

    y = [0] * 16
    vec_h = [ord(c) for c in h]

    for i in range(0, len(x), 16):
        block = [ord(c) for c in x[i:i+16]]
        y = [y[j] ^ block[j] for j in range(16)]
        y = gcm_gf_mult(y, vec_h)

    return ''.join(chr(c) for c in y)

def inc32(block):
    counter, = unpack('>L', block[12:])
    counter += 1
    return block[:12] + pack('>L', counter)

def gctr(k, icb, plaintext):
    y = ''
    if len(plaintext) == 0:
        return y

    aes = AES.new(k)
    cb = icb

    for i in range(0, len(plaintext), aes.block_size):
        cb = inc32(cb)
        encrypted = aes.encrypt(cb)
        plaintext_block = plaintext[i:i+aes.block_size]
        y += strxor.strxor(plaintext_block, encrypted[:len(plaintext_block)])

    return y

def gcm_decrypt(k, iv, encrypted, auth_data, tag):
    aes = AES.new(k)
    h = aes.encrypt(chr(0) * aes.block_size)

    if len(iv) == 12:
        y0 = iv + "\x00\x00\x00\x01"
    else:
        y0 = ghash(h, '', iv)

    decrypted = gctr(k, y0, encrypted)
    s = ghash(h, auth_data, encrypted)

    t = aes.encrypt(y0)
    T = strxor.strxor(s, t)
    if T != tag:
        raise ValueError('Decrypted data is invalid')
    else:
        return decrypted

def gcm_encrypt(k, iv, plaintext, auth_data):
    aes = AES.new(k)
    h = aes.encrypt(chr(0) * aes.block_size)

    if len(iv) == 12:
        y0 = iv + "\x00\x00\x00\x01"
    else:
        y0 = ghash(h, '', iv)

    encrypted = gctr(k, y0, plaintext)
    s = ghash(h, auth_data, encrypted)

    t = aes.encrypt(y0)
    T = strxor.strxor(s, t)
    return (encrypted, T)

def main():
    #http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
    k = 'AD7A2BD03EAC835A6F620FDCB506B345'.decode("hex")
    p = ''
    a = 'D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001'.decode("hex")
    iv = '12153524C0895E81B2C28465'.decode("hex")
    c, t = gcm_encrypt(k, iv, '', a)
    assert c == ""
    assert t == "f09478a9b09007d06f46e9b6a1da25dd".decode("hex")

    k = 'AD7A2BD03EAC835A6F620FDCB506B345'.decode("hex")
    p = '08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002'.decode("hex")
    a = 'D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81'.decode("hex")
    iv = '12153524C0895E81B2C28465'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == '701AFA1CC039C0D765128A665DAB69243899BF7318CCDC81C9931DA17FBE8EDD7D17CB8B4C26FC81E3284F2B7FBA713D'.decode("hex")
    assert t == '4F8D55E7D3F06FD5A13C0C29B9D5B880'.decode("hex")

    key = "91bfb6cbcff07b93a4c68bbfe99ac63b713f0627025c0fb1ffc5b0812dc284f8".decode("hex")
    data = "020000000B00000028000000DE44D22E96B1966BAEF4CBEA8675871D40BA669401BD4EBB52AF9C025134187E70549012058456BF0EC0FA1F8FF9F822AC4312AB2141FA712E6D1482358EAC1421A1BFFA81EF38BD0BF2E52675D665EFE3C534E188F575774FAA92E74345575E370B9982661FAE8BD9243B7AD7D2105B275424C0CA1145B9D43AFF04F2747E40D62EC60563960D62A894BE66F267B14D75C0572BE60CC9B339D440FCB418D4F729BBF15C14E0D3A43E4A8B44523D8B3B0F3E7DF85AA67A707EE19CB893277D2392234D7DBC17DA4A0BD7F166189FC54C16C20D287E20FD2FB11BD2CE09ADBDABB95124CD4BFE219E34D3C80E69570A5A506555D7094916C5D75E0065F1796F556EDF0DAA1AA758E0C85AE3951BD363F26B1D43F6CBAEE12D97AD3B60CFA89C1C76BB29F2B54BE31B6CE166F4860C5E5DA92588EF53AA946DF159E60E6F05009D12FB1E37".decode("hex")
    ciphertext = data[12+40:-16]
    tag = data[-16:]
    print repr(gcm_decrypt(key, '', ciphertext, '', tag))

    # Test vectors from NIST GCM spec
    # http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

    # Test Case 1
    k = '00000000000000000000000000000000'.decode("hex")
    p = ''.decode("hex")
    iv = '000000000000000000000000'.decode("hex")
    a = ''.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == ""
    assert t == "58e2fccefa7e3061367f1d57a4e7455a".decode("hex")

    # Test Case 2
    k = '00000000000000000000000000000000'.decode("hex")
    p = '00000000000000000000000000000000'.decode("hex")
    a = ''.decode("hex")
    iv = '000000000000000000000000'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "0388dace60b6a392f328c2b971b2fe78".decode("hex")
    assert t == "ab6e47d42cec13bdf53a67b21257bddf".decode("hex")

    # Test Case 3
    k = 'feffe9928665731c6d6a8f9467308308'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'.decode("hex")
    a = ''.decode("hex")
    iv = 'cafebabefacedbaddecaf888'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985".decode("hex")
    assert t == "4d5c2af327cd64a62cf35abd2ba6fab4".decode("hex")

    # Test Case 4
    k = 'feffe9928665731c6d6a8f9467308308'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'.decode("hex")
    a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'.decode("hex")
    iv = 'cafebabefacedbaddecaf888'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091".decode("hex")
    assert t == "5bc94fbc3221a5db94fae95ae7121a47".decode("hex")

    # Test Case 5
    k = 'feffe9928665731c6d6a8f9467308308'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'.decode("hex")
    a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'.decode("hex")
    iv = 'cafebabefacedbad'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598".decode("hex")
    assert t == "3612d2e79e3b0785561be14aaca2fccb".decode("hex")

    # Test Case 6
    k = 'feffe9928665731c6d6a8f9467308308'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'.decode("hex")
    a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'.decode("hex")
    iv = '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5".decode("hex")
    assert t == "619cc5aefffe0bfa462af43c1699d050".decode("hex")

    # Test Case 7
    k = '000000000000000000000000000000000000000000000000'.decode("hex")
    p = ''.decode("hex")
    a = ''.decode("hex")
    iv = '000000000000000000000000'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "".decode("hex")
    assert t == "cd33b28ac773f74ba00ed1f312572435".decode("hex")

    # Test Case 8
    k = '000000000000000000000000000000000000000000000000'.decode("hex")
    p = '00000000000000000000000000000000'.decode("hex")
    a = ''.decode("hex")
    iv = '000000000000000000000000'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "98e7247c07f0fe411c267e4384b0f600".decode("hex")
    assert t == "2ff58d80033927ab8ef4d4587514f0fb".decode("hex")

    # Test Case 9
    k = 'feffe9928665731c6d6a8f9467308308feffe9928665731c'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'.decode("hex")
    a = ''.decode("hex")
    iv = 'cafebabefacedbaddecaf888'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256".decode("hex")
    assert t == "9924a7c8587336bfb118024db8674a14".decode("hex")

    # Test Case 10
    k = 'feffe9928665731c6d6a8f9467308308feffe9928665731c'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'.decode("hex")
    a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'.decode("hex")
    iv = 'cafebabefacedbaddecaf888'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710".decode("hex")
    assert t == "2519498e80f1478f37ba55bd6d27618c".decode("hex")

    # Test Case 11
    k = 'feffe9928665731c6d6a8f9467308308feffe9928665731c'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'.decode("hex")
    a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'.decode("hex")
    iv = 'cafebabefacedbad'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7".decode("hex")
    assert t == "65dcc57fcf623a24094fcca40d3533f8".decode("hex")

    # Test Case 12
    k = 'feffe9928665731c6d6a8f9467308308feffe9928665731c'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'.decode("hex")
    a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'.decode("hex")
    iv = '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b".decode("hex")
    assert t == "dcf566ff291c25bbb8568fc3d376a6d9".decode("hex")

    # Test Case 13
    k = '0000000000000000000000000000000000000000000000000000000000000000'.decode("hex")
    p = ''.decode("hex")
    a = ''.decode("hex")
    iv = '000000000000000000000000'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "".decode("hex")
    assert t == "530f8afbc74536b9a963b4f1c4cb738b".decode("hex")

    # Test Case 14
    k = '0000000000000000000000000000000000000000000000000000000000000000'.decode("hex")
    p = '00000000000000000000000000000000'.decode("hex")
    a = ''.decode("hex")
    iv = '000000000000000000000000'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "cea7403d4d606b6e074ec5d3baf39d18".decode("hex")
    assert t == "d0d1c8a799996bf0265b98b5d48ab919".decode("hex")

    # Test Case 15
    k = 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'.decode("hex")
    a = ''.decode("hex")
    iv = 'cafebabefacedbaddecaf888'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad".decode("hex")
    assert t == "b094dac5d93471bdec1a502270e3cc6c".decode("hex")

    # Test Case 16
    k = 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'.decode("hex")
    a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'.decode("hex")
    iv = 'cafebabefacedbaddecaf888'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662".decode("hex")
    assert t == "76fc6ece0f4e1768cddf8853bb2d551b".decode("hex")

    # Test Case 17
    k = 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'.decode("hex")
    a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'.decode("hex")
    iv = 'cafebabefacedbad'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f".decode("hex")
    assert t == "3a337dbf46a792c45e454913fe2ea8f2".decode("hex")

    # Test Case 18
    k = 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'.decode("hex")
    p = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'.decode("hex")
    a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'.decode("hex")
    iv = '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f".decode("hex")
    assert t == "a44a8266ee1c8eb0c8b5d4cf5ae9f19a".decode("hex")


if __name__ == '__main__':
    main()
