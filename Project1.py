import tqdm


def bytes_to_bits(byte_data):

    bits = []
    for byte in byte_data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    byte_arr = []
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        byte_arr.append(byte)
    return bytes(byte_arr)

def strbits_to_bits(s):
    return [int(c) for c in s.strip() if c in "01"]

def xor_bits(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def A5_algo(x_state, y_state, z_state, num_bits):
    # the algorithm will be by finding the majority and then XORing the regisetrs based on the majority
    generated_keystream = []
    for _ in range(num_bits):
        majority = 1 if (x_state[8] + y_state[10] + z_state[10]) >= 2 else 0

        if x_state[8] == majority:
            new_bit = x_state[13] ^ x_state[16] ^ x_state[17] ^ x_state[18]
            x_state = [new_bit] + x_state[:-1]

        if y_state[10] == majority:
            new_bit = y_state[20] ^ y_state[21]
            y_state = [new_bit] + y_state[:-1]

        if z_state[10] == majority:
            new_bit = z_state[7] ^ z_state[20] ^ z_state[21] ^ z_state[22]
            z_state = [new_bit] + z_state[:-1]

        generated_keystream.append(x_state[18] ^ y_state[21] ^ z_state[22])

    return generated_keystream

def brute_force_attack(keystream_bits, x_state, z_state):
    keystream_len = len(keystream_bits)
    # We are using tqdm library to track the y state
    #So it try every possible binary number unti 2^22 - 1
    for i in tqdm.tqdm(range(2**22), desc="Brute-forcing Y"):
        y_state = [int(b) for b in f"{i:022b}"]
        X, Y, Z = x_state.copy(), y_state.copy(), z_state.copy()
        match = True
        #Here we implement the algorthim of a5 /1
        for kb in keystream_bits:
            #Checking the majority if there is 2 with 1 then the majority 1 and else is 0
            majority = 1 if (X[8] + Y[10] + Z[10]) >= 2 else 0
            if X[8] == majority:
                #Based on the slides and our study here is the bits we need to XOR to find the keystream bits.
                new_bit = X[13] ^ X[16] ^ X[17] ^ X[18]
                X = [new_bit] + X[:-1]
            if Y[10] == majority:
                new_bit = Y[20] ^ Y[21]
                Y = [new_bit] + Y[:-1]
            if Z[10] == majority:
                new_bit = Z[7] ^ Z[20] ^ Z[21] ^ Z[22]
                Z = [new_bit] + Z[:-1]
            #The key will be by XORing the least significant bits of each register.
            gen_bit = X[18] ^ Y[21] ^ Z[22]
            if gen_bit != kb:
                match = False
                break
        if match:
            return y_state
    return None

def main():
    #Based on the project,We should take the full path from the user.
    init_state = input("Please enter the initial state file path: ").strip().strip('"')
    known_plaintext_file = input("Please enter the known plain text file path: ").strip().strip('"')
    cipher_text_file = input("Please enter the cipher text file path: ").strip().strip('"')

    #Staring readin the files
    with open(init_state, "r") as f:
        #Readlines is going to read the whole text file into list
        lines = f.readlines()
    #This is going to convert the lines into integer first one for x and second one is for z.
    x_state = [int(b) for b in lines[0].strip()]
    z_state = [int(b) for b in lines[1].strip()]

    #Here the knwon plaintext is going to read it as bytes and then we convert it into bits.
    with open(known_plaintext_file, "r") as f:
        known_plaintext = f.read().encode("ascii")
    plaintext_bits = bytes_to_bits(known_plaintext)
    #this one is going to be in raw bytes.
    with open(cipher_text_file, "rb") as f:
        ciphertext_raw = f.read().decode().strip()
    ciphertext_bits = strbits_to_bits(ciphertext_raw)

    keystream_bits = xor_bits(plaintext_bits, ciphertext_bits[:len(plaintext_bits)])

    y_state = brute_force_attack(keystream_bits, x_state, z_state)
    if y_state is None:
        print("No matching Y state found.")
        return
    print("Found matching Y state:", "".join(map(str, y_state)))

    with open("recovered_y_state.txt", "w") as f:
        f.write("".join(map(str, y_state)))

    full_keystream_bits = A5_algo(x_state.copy(), y_state.copy(), z_state.copy(), len(ciphertext_bits))

    plaintext_bits_full = xor_bits(ciphertext_bits, full_keystream_bits)
    plaintext_bytes = bits_to_bytes(plaintext_bits_full)

    with open("recovered_plaintext.txt", "wb") as f:
        f.write(plaintext_bytes)

    print("Decryption complete. Results saved to recovered_y_state.txt and recovered_plaintext.txt.")

main()

#"C:\Users\tareq\Downloads\initial_states (1).txt"
#C:\Users\tareq\Downloads\known_plaintext.txt
#C:\Users\tareq\Downloads\ciphertext.bin
