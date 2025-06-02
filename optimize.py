from hashlib import sha256
from Crypto.Util.number import getPrime, getRandomRange, long_to_bytes

# ALT_BN128 prime field
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def bytes_to_u32_list(b):
    return [int.from_bytes(b[i:i+4], 'big') for i in range(0, len(b), 4)]

def pack_u32_to_field(u32_list):
    # Pack 4 u32s (128 bits) into one field element (integer)
    result = 0
    for i, v in enumerate(u32_list):
        result += v << (32 * (3 - i))  # Big-endian, highest u32 first
    return result % p

def gamma_to_bytes_and_fields(gamma):
    gamma_bytes = long_to_bytes(gamma).rjust(64, b'\x00')  # 512 bits, 64 bytes
    gamma_u32 = bytes_to_u32_list(gamma_bytes)  # 16 u32's
    gamma_fields = []
    for i in range(4):
        chunk = gamma_u32[i*4:(i+1)*4]
        gamma_fields.append(pack_u32_to_field(chunk))
    return gamma_fields, gamma_bytes, gamma_u32

def hash_512bit_packed(gamma_fields):
    # Convert field[4] back to 64 bytes for hashing
    gamma_bytes = b''
    for field in gamma_fields:
        gamma_bytes += field.to_bytes(16, 'big')  # Each field is 128 bits = 16 bytes
    digest = sha256(gamma_bytes).digest()
    digest_u32 = bytes_to_u32_list(digest)
    hash_fields = []
    for i in range(2):
        chunk = digest_u32[i*4:(i+1)*4]
        hash_fields.append(pack_u32_to_field(chunk))
    return hash_fields

def main():
    # Gen is a 512-bit prime number
    gen = getPrime(512)
    # Gamma is a random number in the range [1, gen - 1]
    gamma = getRandomRange(1, gen - 1)

    gamma_fields, gamma_bytes, gamma_u32 = gamma_to_bytes_and_fields(gamma)
    hash_fields = hash_512bit_packed(gamma_fields)
    #Gamma32 is the first field element modulo 2^32
    GAMMA32 = gamma_fields[0] % (2**32)
    # c is the generator raised to the power of GAMMA32 modulo p
    c = pow(gen, GAMMA32, p)
    print(f"gamma = {gamma}")
    print("// gamma as field[4]:")
    print("[" + ", ".join(f'"{x}"' for x in gamma_fields) + "]")
    print("// hash_gamma as field[2]:")
    print("[" + ", ".join(f'"{x}"' for x in hash_fields) + "]")
    print(f"gen = {gen}")
    print(f"GAMMA32 = {GAMMA32}")
    print(f"c = {c}")

if __name__ == "__main__":
    main()