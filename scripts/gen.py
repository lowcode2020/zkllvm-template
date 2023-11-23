from hashlib import sha256
from bitstring import BitArray
import random
from typing import List

ALL_LEAFS = [
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    bytes.fromhex("db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
    bytes.fromhex("c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
    bytes.fromhex("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
    bytes.fromhex("9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
    bytes.fromhex("d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1"),
    bytes.fromhex("87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
    bytes.fromhex("26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"),
    bytes.fromhex("506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1"),
    bytes.fromhex("ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
    bytes.fromhex("6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220"),
    bytes.fromhex("b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f"),
    bytes.fromhex("df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e"),
    bytes.fromhex("b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784"),
    bytes.fromhex("d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb"),
    bytes.fromhex("8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb"),
    bytes.fromhex("8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab"),
    bytes.fromhex("95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4"),
    bytes.fromhex("f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f"),
    bytes.fromhex("cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa"),
    bytes.fromhex("8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c"),
    bytes.fromhex("feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167"),
    bytes.fromhex("e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7"),
    bytes.fromhex("31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0"),
    bytes.fromhex("21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544"),
    bytes.fromhex("619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765"),
    bytes.fromhex("7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4"),
    bytes.fromhex("848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1"),
    bytes.fromhex("8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636"),
    bytes.fromhex("b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c"),
    bytes.fromhex("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7"),
]

def slice_into_chunks(lst, chunk_len, fillvalue):
    """
    Slices lst into non-overlapping lists of `chunk_len`.
    The last chunk is padded to full length with fillvalue

    Examples:
    >>> slice_into_chunks([1,2,3,4,5,6], 2, -1) == [[1,2], [3,4], [5,6]]
    >>> slice_into_chunks([1,2,3,4,5,6], 3, -1) == [[1,2,3], [4,5,6]]
    >>> slice_into_chunks([1,2,3,4,5,6,7,8], 3, -1) == [[1,2,3], [4,5,6], [7,8,-1]]
    """
    remainder = len(lst) % chunk_len
    if remainder != 0:
        lst += [fillvalue] * (chunk_len - remainder)
    sliced_list = [lst[i:i+chunk_len] for i in range(0, len(lst), chunk_len)]
    return sliced_list

def slice_into_low_high(digest):
    # assert(len(digest) == 32)
    low = int.from_bytes(digest[:16], 'big')
    high = int.from_bytes(digest[16:], 'big')

    print (str(hex(low))+ "_cppui255", str(hex(high))+ "_cppui255")
    # print(low, high)
    return low, high


def print_array(array, bytes_or_bits='bytes'):
    if bytes_or_bits == 'bytes':
        print(list(value.hex() for value in array))
    elif bytes_or_bits == 'bits':
        print(list(BitArray(value).bin for value in array))

def uint64_to_bytes(value) -> bytes:
    return value.to_bytes(8, 'little', signed=False)

def pack(value1, value2, value3, value4):
    """
    Packs 4 numbers into 32 byte (256 bit) block, little endian, unsigned
    Note that (-1).to_bytes(..., signed=False) DO NOT result in 2-complement, but raises an exception
    pack(1,2,3,4) == b'\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'
    """
    assert(value1 > 0 and value2 > 0 and value3 > 0 and value4 > 0)
    result = uint64_to_bytes(value1) + uint64_to_bytes(value2) + uint64_to_bytes(value3) + uint64_to_bytes(value4)
    assert(len(result) == 32)
    return result

def get_fixed_balances(count=50) -> List[int]:
    return [i for i in range(1, count+1)]

def hash_pair(first: bytes, second: bytes) -> bytes:
    inp = first + second
    return sha256(inp).digest()

if __name__ == "__main__":

    # hash_res = hash_pair(ZEROHASHES[0], ZEROHASHES[1])

    # slice_into_low_high(ZEROHASHES[0])
    # # print(BitArray(ZEROHASHES[0]).bin)
    
    # slice_into_low_high(ZEROHASHES[1])
    # # print(BitArray(ZEROHASHES[1]).bin)
    
    # # print (hash_res)
    # slice_into_low_high(hash_res)

    # balances = get_fixed_balances(count=20)
    # packed_chunks = [pack(v1, v2, v3, v4) for (v1, v2, v3, v4) in slice_into_chunks(balances, 4, 0)]
    # print("Merkle leafs:")
    # print_array(packed_chunks, 'bits')
    i = 0
    for zerohash in ZEROHASHES:
        print (str(2**i) )
        # slice_into_low_high(zerohash)
        i += 1