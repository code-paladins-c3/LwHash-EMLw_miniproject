def bytes_to_hex_string(data: bytes) -> str:
    return data.hex()

def string_to_bytes(s: str) -> bytes:
    return s.encode('utf-8')

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    if len(b1) != len(b2):
        raise ValueError("Objetos bytes devem ter o mesmo tamanho para XOR.")
    return bytes(x ^ y for x, y in zip(b1, b2))

def rotr64(x: int, n: int) -> int:
    n %= 64
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def rotl64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def bytes_to_uint64_le(b: bytes) -> int:
    if len(b) != 8:
        raise ValueError("Input bytes must be 8 bytes long for uint64 conversion.")
    return int.from_bytes(b, byteorder='little')

def uint64_to_bytes_le(n: int) -> bytes:
    return n.to_bytes(8, byteorder='little', signed=False)

def rol16(v: int, n: int) -> int:
    n %= 16
    return ((v << n) | (v >> (16 - n))) & 0xFFFF

def rol32(v: int, n: int) -> int:
    n %= 32
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF
