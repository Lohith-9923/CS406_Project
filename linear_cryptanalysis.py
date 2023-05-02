# A basic Substitution-Permutation Network cipher, implemented by following
# 'A Tutorial on Linear and Differential Cryptanalysis' by Howard M. Heys
# Basic SPN cipher which takes as input a 16-bit input block and has 4 rounds.

import random
import hashlib
from math import fabs
import collections

BLOCK_SIZE = 16

# (1) Substitution: 4x4 bijective, one sbox used for all 4 sub-blocks of size 4. Nibble wise
sbox = {0: 0xA, 1: 0x4, 2: 0xD, 3: 0x1, 4: 0x2, 5: 0xF, 6: 0xB, 7: 0x8, 8: 0x3,
        9: 0xE, 0xA: 0x6, 0xB: 0xC, 0xC: 0x5, 0xD: 0x9, 0xE: 0x0, 0xF: 0x7}  # key:value
sbox_inv = {0xA: 0, 0x4: 1, 0xD: 2, 0x1: 3, 0x2: 4, 0xF: 5, 0xB: 6, 0x8: 7,
            0x3: 8, 0xE: 9, 0x6: 0xA, 0xC: 0xB, 0x5: 0xC, 0x9: 0xD, 0x0: 0xE, 0x7: 0xF}

# Apply sbox (1) to a 16 bit state and return the result


def get_sbox(state, sbox):
    a = state & 0x000f
    b = state & 0x00f0
    c = state & 0x0f00
    d = state & 0xf000
    subStates = [a, b >> 4, c >> 8, d >> 12]
    for idx, subState in enumerate(subStates):
        subStates[idx] = sbox[subState]
    return subStates[0] | subStates[1] << 4 | subStates[2] << 8 | subStates[3] << 12


pbox = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]


def permute(state):
    temp = 0
    for bit_index in range(0, BLOCK_SIZE):
        if (state & (1 << bit_index)):
            temp |= (1 << pbox[bit_index])
    return temp

# (2) Permutation. Applied bit-wise
# (3) Key mixing: bitwise XOR between round subkey and data block input to round

# Key schedule: independant random round keys.
# We take the sha-hash of a 128-bit 'random' seed and then take the first 80-bits
# of the output as out round keys K1-K5 (Each 16 bits long).


def keyGen():
    k = hashlib.sha256(
        hex(random.getrandbits(128)).encode('utf-8')).hexdigest()
    k = k[:20]
    return k

# Simple SPN Cipher encrypt function


def encrypt(plaintext, key):
    state = plaintext

    subKeys = [int(subK, 16)
               for subK in [key[0:4], key[4:8], key[8:12], key[12:16], key[16:20]]]

    # First three rounds of sinple SPN cipher
    for round_no in range(0, 3):
        # XOR state with round key (3, subkeys 1,..,4)
        state = state ^ subKeys[round_no]
        # Break state into nibbles, perform sbox on each nibble, write to state (1)
        state = get_sbox(state, sbox)
        # Permute the state bitwise (2)
        state = permute(state)

    state = state ^ subKeys[-2]  # penultimate subkey (key 4) mixing
    state = get_sbox(state, sbox)
    state = state ^ subKeys[-1]  # Final subkey (key 5) mixing

    return state

# Simple SPN Cipher decrypt function


def decrypt(ciphertext, k):
    state = ciphertext
    # Derive round keys
    subKeys = [int(subK, 16)
               for subK in [k[0:4], k[4:8], k[8:12], k[12:16], k[16:20]]]

    # Undo final round key
    state = state ^ subKeys[4]

    # Apply inverse s-box
    state = get_sbox(state, sbox_inv)

    # Undo first 3 rounds of simple SPN cipher
    for round_no in range(3, 0, -1):

        # XOR state with round key (3, subkeys 4,..,0)
        state = state ^ subKeys[round_no]
        # Un-permute the state bitwise (2)
        state = permute(state)
        # Apply inverse s-box
        state = get_sbox(state, sbox_inv)

    # XOR state with round key 0
    state = state ^ subKeys[0]

    return state

############################# END OF ENCRYPTION AND DECRYPTION #################################################

############################# LINEAR CRYPTANALYSIS START #######################################################


def linear_crypt():
    # # Build table of input values
    sbox_in = []
    for i in range(2):
        for j in range(2):
            for k in range(2):
                for l in range(2):
                    sbox_in.append(str(i)+str(j)+str(k)+str(l))
    # Build a table of output values
    sbox_out = [bin(sbox[int(seq, 2)])[2:].zfill(4) for seq in sbox_in]
    # Build an ordered dictionary between input and output values
    sbox_b = collections.OrderedDict(zip(sbox_in, sbox_out))
    # Initialise the Linear Approximation Table (LAT)
    prob_bias = []
    for i in range(len(sbox_b)):
        a = []
        for j in range(len(sbox_b)):
            a.append(0)
        prob_bias.append(a)
    # A complete enumeration of all the linear approximations of the simple SPN
    # cipher S-Box. Dividing an element value by 16 gives the probability bias
    # for the particular linear combination of input and output bits.
    print('Linear Approximation Table for basic SPN cipher\'s sbox: ')
    print('(x-axis: output equation - 8, y-axis: input equation)')
    for bits in sbox_b.items():
        inp, out = bits
        x, y, z, w = [int(bits, 2) for bits in [
            inp[0], inp[1], inp[2], inp[3]]]
        a, b, c, d = [int(bits, 2) for bits in [
            out[0], out[1], out[2], out[3]]]

        eq_in = [0, w, z, z ^ w, y, y ^ w, y ^ z, y ^ z ^ w, x, x ^ w,
                 x ^ z, x ^ z ^ w, x ^ y, x ^ y ^ w, x ^ y ^ z, x ^ y ^ z ^ w]

        eq_out = [0, d, c, c ^ d, b, b ^ d, b ^ c, b ^ c ^ d, a, a ^ d,
                  a ^ c, a ^ c ^ d, a ^ b, a ^ b ^ d, a ^ b ^ c, a ^ b ^ c ^ d]

        for x_index in range(0, len(eq_in)):
            for y_index in range(0, len(eq_out)):
                prob_bias[x_index][y_index] += (eq_in[x_index]
                                                == eq_out[y_index])

    # Print the linear approximation table
    for bias in prob_bias:
        for i in bias:
            print('{:d}'.format(i-8).zfill(2), end=' ')
        print('')

    # Using the LAT, we can construct the following equation that holds with
    # probability 0.75. Let U_{i} and V_{i} represent the 16-bit block of bits
    # at the input and output of the round i S-Boxes, respectively, and let
    # K_{i,j} represent the j\'th bit of the subkey block of bits exclusive-ORed
    # at the input to round i. Also let P_{i} represent the i\'th input bit, then
    #
    # U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16}⊕P_{5}⊕P_{7}⊕P_{8}⊕SUM(K) = 0 where
    #
    # SUM(K) = K_{1,5}⊕K_{1,7}⊕K_{1,8}⊕K_{2,6}⊕K_{3,6}⊕K_{3,14}⊕K_{4,6}⊕K_{4,8}⊕K_{4,14}⊕K_{4,16}
    #
    # holds with a probability of 15/32 (with a bias of 1/32).
    # Since sum(K) is fixed (by the key, k), U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16}⊕P_{5}⊕P_{7}⊕P_{8} = 0
    # must hold with a probability of either 15/32 or 1-15/32. In other words we
    # now have a linear approximation of the first three rounds of the cipher with
    # a bias of magnitude 1/32.
    k = keyGen()
    k_5 = int(k, 16) & 0xffff  # Just last 16 bits are K5
    k_5_5_8 = (k_5 >> 8) & 0b1111
    k_5_13_16 = k_5 & 0b1111

    print('\nTest key k = {:}'.format(k), end=' ')
    print('(k_5 = {:}).'.format(hex(k_5).zfill(4)))
    print('Target partial subkey K_5,5...k_5,8 = 0b{:} = 0x{:}'.format(
        bin(k_5_5_8)[2:].zfill(4), hex(k_5_5_8)[2:].zfill(1)))
    print('Target partial subkey K_5,13...k_5,16 = 0b{:} = 0x{:}'.format(
        bin(k_5_13_16)[2:].zfill(4), hex(k_5_13_16)[2:].zfill(1)))
    print('Testing each target subkey value...')

    cnt = []
    for i in range(256):
        cnt.append(0)

    for plaintext in range(10000):
        ciphertext = encrypt(plaintext, k)
        ciphertext_5_8 = (ciphertext >> 8) & 0b1111
        ciphertext_13_16 = ciphertext & 0b1111
        # For each target partial subkey value k_5|k_8|k_13|k_16 in [0,255],
        # increment the cnt whenever equation (5) holds true,
        for target in range(256):
            target_5_8 = (target >> 4) & 0b1111
            target_13_16 = target & 0b1111
            v_5_8 = (ciphertext_5_8 ^ target_5_8)
            v_13_16 = (ciphertext_13_16 ^ target_13_16)
            # for target_13_16 in range(16):
            # Does U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16}⊕P_{5}⊕P_{7}⊕P_{8}⊕SUM(K) = 0?

            # (1) Compute U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16} by running the ciphertext
            # backwards through the target partial subkey and S-Boxes.
            # xor ciphertext with subKey bits

            # (2) Run backwards through s-boxes
            u_5_8, u_13_16 = sbox_inv[v_5_8], sbox_inv[v_13_16]

            # (3) Compute linear approximation U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16}⊕P_{5}⊕P_{7}⊕P_{8}
            lApprox = ((u_5_8 >> 2) & 0b1) ^ (u_5_8 & 0b1) ^ ((u_13_16 >> 2) & 0b1) ^ (
                u_13_16 & 0b1) ^ ((plaintext >> 11) & 0b1) ^ ((plaintext >> 9) & 0b1) ^ ((plaintext >> 8) & 0b1)
            if lApprox == 0:
                cnt[target] += 1

    # The cnt which deviates the largest from half of the number of
    # plaintext/ciphertext samples is assumed to be the correct value.
    bias = []
    for i in cnt:
        bias.append(fabs(i - 5000.0)/10000.0)
    maxResult, max_index = 0, 0
    for rIdx, result in enumerate(bias):
        if result > maxResult:
            maxResult = result
            max_index = rIdx

    print('Highest bias is {:} for subKey value {:}.'.format(
        maxResult, hex(max_index)))
    if (max_index >> 4) & 0b1111 == k_5_5_8 and max_index & 0b1111 == k_5_13_16:
        print('PASS!!')
    else:
        print('Failure!!!!')


if __name__ == "__main__":

    # Generate a randon key
    k = keyGen()
    l = k
    # Produce a CSV of plaintext, key value pairs for cryptanalysis
    fileName = 'results/' + k[0:20] + '.csv'
    nVals = 10000
    r = list(range(nVals))
    random.shuffle(r)
    file = open(fileName, "w+")
    print('Running basic SPN cipher with key K = {:}'.format(k))

    # file.write('test')
    for i in r:
        a = encrypt(i, k)
        file.write('{:04x}, {:04x}, {:04x}\n'.format(i, a, decrypt(a, k)))

    file.close()

    print('Simple SPN plaintext, ciphertext CSV written to ' + fileName)
    print('{:} values written.'.format(nVals))

    linear_crypt()
