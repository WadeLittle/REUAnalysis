from hashlib import sha256
from Crypto.Util.number import getRandomRange

FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
CURVE_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617

class FQ(int):
    modulus = FIELD_MODULUS
    def __new__(cls, value):
        return int.__new__(cls, value % cls.modulus)
    def __add__(self, other): return FQ(int(self) + int(other))
    def __sub__(self, other): return FQ(int(self) - int(other))
    def __mul__(self, other): return FQ(int(self) * int(other))
    def __truediv__(self, other): return FQ(int(self) * pow(int(other), -1, self.modulus))
    def __pow__(self, exp, mod=None): return FQ(pow(int(self), exp, self.modulus))
    @property
    def n(self): return int(self)

def int_to_bits(n, width=256):
    return [int(x) for x in bin(n)[2:].zfill(width)]

def bits_to_bool_str(bits):
    return " ".join(str(b) for b in bits)

def sha256_to_u32_list(val: int):
    b = val.to_bytes(32, 'big')
    digest = sha256(b).digest()
    return [int.from_bytes(digest[i:i+4], 'big') for i in range(0, 32, 4)]

def point_to_fields(pt):
    if pt is None:
        return [0, 0]
    return [int(pt[0].n) % FIELD_MODULUS, int(pt[1].n) % FIELD_MODULUS]

def print_array(arr):
    print("[" + ", ".join(f'"{x}"' for x in arr) + "]")

def print_bool_array(arr):
    arr = arr[::-1]
    print("[" + ", ".join("true" if x else "false" for x in arr) + "]")

def print_bool_array_le(arr):
    arr = arr[::-1]
    print("[" + ", ".join("true" if x else "false" for x in arr) + "]")

def print_bool_array_be(arr):
    print("[" + ", ".join("true" if x else "false" for x in arr) + "]")

def pack_bits(bits):
    return sum((1 << (255 - i)) if b else 0 for i, b in enumerate(bits))

def write_input_file(filename, gamma_bits, beta_bits, b_g_scalar_bits, hash_gamma, gen, gg, gb, c_star):
    with open(filename, "w") as f:
        for b in gamma_bits:
            f.write(f"{int(b)}\n")
        for b in beta_bits:
            f.write(f"{int(b)}\n")
        for b in b_g_scalar_bits:
            f.write(f"{int(b)}\n")
        for x in hash_gamma:
            f.write(f"{x}\n")
        for arr in [gen, gg, gb, c_star]:
            for x in arr:
                f.write(f"{x}\n")

# Elliptic curve: y^2 = x^3 + 3 over FQ
def is_inf(pt):
    return pt is None

def double(pt):
    if is_inf(pt):
        return None
    x, y = pt
    if y == 0:
        return None
    l = (FQ(3) * x * x) / (FQ(2) * y)
    newx = l * l - FQ(2) * x
    newy = l * (x - newx) - y
    return (newx, newy)

def add(p1, p2):
    if is_inf(p1):
        return p2
    if is_inf(p2):
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 == y2:
        return double(p1)
    if x1 == x2:
        return None
    l = (y2 - y1) / (x2 - x1)
    newx = l * l - x1 - x2
    newy = l * (x1 - newx) - y1
    return (newx, newy)

def multiply(pt, n):
    if n == 0 or is_inf(pt):
        return None
    result = None
    addend = pt
    for i in range(256):
        if (n >> (255 - i)) & 1:
            result = add(result, addend)
        addend = double(addend)
    return result

def main():
    G1 = (FQ(1), FQ(2))

    # Generate random 256-bit scalars with MSB set
    while True:
        gamma = getRandomRange(1, CURVE_ORDER - 1)
        gamma_bits = int_to_bits(gamma)
        if pack_bits(gamma_bits) != 0:
            break

    while True:
        beta = getRandomRange(1, CURVE_ORDER - 1)
        beta_bits = int_to_bits(beta)
        if pack_bits(beta_bits) != 0:
            break

    # Hash gamma
    hash_gamma = sha256_to_u32_list(gamma)

    # Use G1 generator
    gen = point_to_fields(G1)

    # Compute gg = gen^gamma, gb = gen^beta
    gg = point_to_fields(multiply(G1, gamma))
    print("gg:", multiply(G1, gamma))
    gb = point_to_fields(multiply(G1, beta))

    # Compute c_star = gen^(beta/gamma) in scalar field
    gamma = gamma % CURVE_ORDER
    beta = beta % CURVE_ORDER
    gamma_inv = pow(gamma, -1, CURVE_ORDER)
    b_g_scalar = (beta * gamma_inv) % CURVE_ORDER
    c_star = point_to_fields(multiply(G1, b_g_scalar))

    # Compute b_g_scalar_bits
    b_g_scalar_bits = int_to_bits(b_g_scalar)

    # Print in ZoKrates input format
    print("// gamma as bool[256]:")
    print_bool_array_be(gamma_bits)  # For hashing

    print("// beta as bool[256]:")
    print_bool_array_be(beta_bits)   # For hashing

    print("// b_g_scalar as bool[256]:")
    print_bool_array_be(b_g_scalar_bits)  # For packing/assertion

    print("// hash_gamma as u32[8]:")
    print_array(hash_gamma)
    print("// gen as field[2]:")
    print_array(gen)
    print("// gg as field[2]:")
    print_array(gg)
    print("// gb as field[2]:")
    print_array(gb)
    print("// c_star as field[2]:")
    print_array(c_star)

    result = multiply(G1, 3)
    print("Result:", result)
    print("gamma int:", gamma)

    write_input_file(
        "zokrates_input.txt",
        gamma_bits,
        beta_bits,
        b_g_scalar_bits,
        hash_gamma,
        gen,
        gg,
        gb,
        c_star
    )

if __name__ == "__main__":
    main()