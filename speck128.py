from utils import rotr64, rotl64, bytes_to_uint64_le, uint64_to_bytes_le

class Speck128KeySchedule:
    def __init__(self, master_key: bytes):
        if len(master_key) != 16:
            raise ValueError("SPECK128/128: Chave mestra deve ter 16 bytes.")
        self.k = [0] * 32
        k0 = bytes_to_uint64_le(master_key[8:16])
        l0 = bytes_to_uint64_le(master_key[0:8])
        l_temp = [0] * 33
        l_temp[0] = l0
        self.k[0] = k0
        for i in range(31):
            l_temp[i+1] = (self.k[i] + rotr64(l_temp[i], 8)) & 0xFFFFFFFFFFFFFFFF
            l_temp[i+1] ^= i
            self.k[i+1] = rotl64(self.k[i], 3) ^ l_temp[i+1]
            self.k[i+1] &= 0xFFFFFFFFFFFFFFFF

def speck128_128_encrypt(plaintext_block: bytes, schedule: Speck128KeySchedule) -> bytes:
    if len(plaintext_block) != 16:
        raise ValueError("SPECK128/128: Bloco de plaintext deve ter 16 bytes.")
    y = bytes_to_uint64_le(plaintext_block[0:8])
    x = bytes_to_uint64_le(plaintext_block[8:16])
    for i in range(32):
        x = (rotr64(x, 8) + y) & 0xFFFFFFFFFFFFFFFF
        x ^= schedule.k[i]
        y = rotl64(y, 3) ^ x
        y &= 0xFFFFFFFFFFFFFFFF
    return uint64_to_bytes_le(x) + uint64_to_bytes_le(y)
