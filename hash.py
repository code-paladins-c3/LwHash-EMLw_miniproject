# --------------------
# utils.py (utilitários)
# --------------------
def bytes_to_hex_string(data: bytes) -> str:
    """Converte bytes para uma string hexadecimal."""
    return data.hex()

def string_to_bytes(s: str) -> bytes:
    """Converte uma string para bytes (UTF-8)."""
    return s.encode('utf-8')

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """Realiza XOR em dois objetos bytes do mesmo tamanho."""
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

# --------------------
# speck128.py
# --------------------
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

# --------------------
# rectangle128.py
# --------------------
RECTANGLE_MASK = 0xFFFF
RECTANGLE_ROUNDS = 25
RECTANGLE_BLOCK_SIZE_BYTES = 8
RECTANGLE_KEY_SIZE_BYTES = 16
RECTANGLE_OFFICIAL_SBOX = [0x6, 0x5, 0xC, 0xA, 0x1, 0xE, 0x7, 0x9, 0xB, 0x0, 0x3, 0xD, 0x8, 0xF, 0x4, 0x2]
RECTANGLE_RC = [0x01, 0x02, 0x04, 0x09, 0x12, 0x05, 0x0B, 0x16, 0x0C, 0x19, 0x13, 0x07, 0x0F, 0x1F, 0x1E, 0x1C, 0x18, 0x11, 0x03, 0x06, 0x0D, 0x1B, 0x17, 0x0E, 0x1D]

class RectangleKeySchedule:
    def __init__(self, master_key: bytes):
        if len(master_key) != RECTANGLE_KEY_SIZE_BYTES:
            raise ValueError("Chave mestra deve ter 128 bits (16 bytes).")
        rows = [int.from_bytes(master_key[i*4:(i+1)*4], "little") for i in range(4)]
        self.round_keys = []
        for r in range(RECTANGLE_ROUNDS + 1):
            k_r = [rows[3] & RECTANGLE_MASK, rows[2] & RECTANGLE_MASK, rows[1] & RECTANGLE_MASK, rows[0] & RECTANGLE_MASK]
            self.round_keys.append(k_r)
            if r == RECTANGLE_ROUNDS:
                break
            for j in range(8):
                nibble = ((rows[3] >> j) & 1) << 3 | ((rows[2] >> j) & 1) << 2 | ((rows[1] >> j) & 1) << 1 | ((rows[0] >> j) & 1)
                s = RECTANGLE_OFFICIAL_SBOX[nibble]
                mask = ~(1 << j)
                for idx in range(4):
                    rows[idx] &= mask
                if s & 0x8:  rows[3] |= (1 << j)
                if s & 0x4:  rows[2] |= (1 << j)
                if s & 0x2:  rows[1] |= (1 << j)
                if s & 0x1:  rows[0] |= (1 << j)
            new_row0 = rol32(rows[0], 8) ^ rows[1]
            new_row1 = rows[2]
            new_row2 = rol32(rows[2], 16) ^ rows[3]
            new_row3 = rows[0]
            rows = [new_row0, new_row1, new_row2, new_row3]
            rows[0] ^= RECTANGLE_RC[r]

def rectangle_encrypt_block(plaintext_block: bytes, schedule: RectangleKeySchedule) -> bytes:
    if len(plaintext_block) != RECTANGLE_BLOCK_SIZE_BYTES:
        raise ValueError("Bloco deve ter exatamente 8 bytes (64 bits).")
    state = [int.from_bytes(plaintext_block[i*2:(i+1)*2], "little") for i in range(4)]
    for r in range(RECTANGLE_ROUNDS):
        rk = schedule.round_keys[r]
        for i in range(4):
            state[i] ^= rk[i]
        for j in range(16):
            nibble = ((state[3] >> j) & 1) << 3 | ((state[2] >> j) & 1) << 2 | ((state[1] >> j) & 1) << 1 | ((state[0] >> j) & 1)
            s = RECTANGLE_OFFICIAL_SBOX[nibble]
            mask = ~(1 << j)
            for idx in range(4):
                state[idx] &= mask
            if s & 0x8:  state[3] |= (1 << j)
            if s & 0x4:  state[2] |= (1 << j)
            if s & 0x2:  state[1] |= (1 << j)
            if s & 0x1:  state[0] |= (1 << j)
        state[1] = rol16(state[1], 1)
        state[2] = rol16(state[2], 12)
        state[3] = rol16(state[3], 13)
    rk = schedule.round_keys[RECTANGLE_ROUNDS]
    for i in range(4):
        state[i] ^= rk[i]
    return b''.join(s.to_bytes(2, "little") for s in state)

def rectangle_encrypt_128bit_wrapper(block128: bytes, schedule: RectangleKeySchedule) -> bytes:
    if len(block128) != 16:
        raise ValueError("Entrada deve ter 128 bits (16 bytes).")
    left  = rectangle_encrypt_block(block128[:8],  schedule)
    right = rectangle_encrypt_block(block128[8:], schedule)
    return left + right

# --------------------
# ctr_mode.py
# --------------------
def ctr_mode_encrypt(data: bytes, nonce: bytes, key_schedule, encrypt_func, cipher_block_size_bytes: int) -> bytes:
    if len(nonce) != cipher_block_size_bytes:
        raise ValueError("Tamanho do Nonce deve ser igual ao tamanho do bloco da cifra.")
    output_data = bytearray()
    current_counter_bytes = bytearray(nonce)
    for i in range(0, len(data), cipher_block_size_bytes):
        keystream_block = encrypt_func(bytes(current_counter_bytes), key_schedule)
        data_chunk = data[i : i + cipher_block_size_bytes]
        output_data.extend(xor_bytes(data_chunk, keystream_block[:len(data_chunk)]))
        val = int.from_bytes(current_counter_bytes, 'big')
        val = (val + 1) & ((1 << (cipher_block_size_bytes * 8)) -1)
        current_counter_bytes = bytearray(val.to_bytes(cipher_block_size_bytes, 'big'))
    return bytes(output_data)

# --------------------
# padding.py
# --------------------
def pad_message(message: bytes, block_size_bytes: int) -> bytes:
    if block_size_bytes == 0:
        raise ValueError("Tamanho do bloco não pode ser zero.")
    padded_message = bytearray(message)
    padded_message.append(0x80)
    current_len_bytes = len(padded_message)
    bytes_to_add = (block_size_bytes - (current_len_bytes % block_size_bytes)) % block_size_bytes
    padded_message.extend(b'\x00' * bytes_to_add)
    return bytes(padded_message)

# --------------------
# lwhash.py (classe principal)
# --------------------
class LwHash:
    def __init__(self, output_bit_len: int, cipher_choice: str, key_bytes: bytes):
        if output_bit_len not in [128, 256, 512]:
            raise ValueError("Tamanho de saída do hash deve ser 128, 256 ou 512 bits.")
        self.output_len_bytes = output_bit_len // 8
        self.cipher_choice = cipher_choice
        self.master_key = key_bytes
        self.internal_digest_size_bytes = self.output_len_bytes
        self.cipher_sub_block_processing_size_bytes = 16
        if self.internal_digest_size_bytes == 64:
            self.num_sub_blocks_per_digest = 4
        elif self.internal_digest_size_bytes == 32:
            self.num_sub_blocks_per_digest = 2
        elif self.internal_digest_size_bytes == 16:
            self.num_sub_blocks_per_digest = 1
        else:
            raise ValueError("Lógica interna incorreta para o tamanho do digest.")
        if self.cipher_choice == "SPECK":
            self.key_schedule = Speck128KeySchedule(self.master_key)
            self.encrypt_func = speck128_128_encrypt
            self.cipher_block_size = 16
        elif self.cipher_choice == "RECTANGLE":
            self.key_schedule = RectangleKeySchedule(self.master_key)
            self.encrypt_func = lambda block, ks: rectangle_encrypt_128bit_wrapper(block, ks)
            self.cipher_block_size = 16
        else:
            raise ValueError("Escolha de cifra inválida. Use 'SPECK' ou 'RECTANGLE'.")
    def _process_message_digest_block(self, message_k_block: bytes, nonce_ctr_start: bytes) -> bytes:
        if len(message_k_block) != self.internal_digest_size_bytes:
            raise ValueError("Tamanho inválido do bloco M_k para processamento.")
        M_sub_blocks = [message_k_block[j*16:(j+1)*16] for j in range(self.num_sub_blocks_per_digest)]
        concatenated_M_sub_blocks = b"".join(M_sub_blocks)
        concatenated_eM_sub_blocks = ctr_mode_encrypt(
            concatenated_M_sub_blocks,
            nonce_ctr_start,
            self.key_schedule,
            self.encrypt_func,
            self.cipher_block_size
        )
        eM_sub_blocks = [concatenated_eM_sub_blocks[j*16:(j+1)*16] for j in range(self.num_sub_blocks_per_digest)]
        block_minihash_temp = eM_sub_blocks[0] if eM_sub_blocks else b'\x00'*16
        for j in range(1, self.num_sub_blocks_per_digest):
            block_minihash_temp = xor_bytes(block_minihash_temp, eM_sub_blocks[j])
        block_minihash = self.encrypt_func(block_minihash_temp, self.key_schedule)
        updated_eM_sub_blocks = [xor_bytes(eM_sub_blocks[j], block_minihash) for j in range(self.num_sub_blocks_per_digest)]
        return b"".join(updated_eM_sub_blocks)
    def compute_hash(self, message: bytes) -> bytes:
        padded_message = pad_message(message, self.internal_digest_size_bytes)
        num_digest_blocks = len(padded_message) // self.internal_digest_size_bytes
        nonce_base_int = int.from_bytes(b'\x52\x0c\x36\xfa' + b'\x00'*12, 'big')
        H_processed_blocks = []
        for i in range(num_digest_blocks):
            current_mk_block = padded_message[i*self.internal_digest_size_bytes:(i+1)*self.internal_digest_size_bytes]
            current_block_ctr_iv_bytes = nonce_base_int.to_bytes(self.cipher_block_size, 'big')
            processed_mk_block = self._process_message_digest_block(current_mk_block, current_block_ctr_iv_bytes)
            H_processed_blocks.append(processed_mk_block)
            nonce_base_int = (nonce_base_int + self.num_sub_blocks_per_digest) & ((1 << (self.cipher_block_size * 8)) -1)
        if not H_processed_blocks:
            return b'\x00' * self.output_len_bytes
        final_hash_value_int = int.from_bytes(H_processed_blocks[0], byteorder='big')
        mask_output_size = (1 << (self.output_len_bytes * 8)) - 1
        for i in range(1, len(H_processed_blocks)):
            block_k_int = int.from_bytes(H_processed_blocks[i], byteorder='big')
            if (i - 1) % 2 == 0:
                final_hash_value_int = (final_hash_value_int + block_k_int) & mask_output_size
            else:
                final_hash_value_int ^= block_k_int
        return final_hash_value_int.to_bytes(self.output_len_bytes, byteorder='big')

# --------------------
# main (testes)
# --------------------
if __name__ == "__main__":
    print("--- Testes LwHash (Python) ---")
    # Teste SPECK
    speck_test_key = bytes.fromhex("00000000000000000000000000000000")
    speck_test_pt = bytes.fromhex("00000000000000000000000000000000")
    speck_test_expected_ct_hex = "410901086c681b07a5c24fc31e9c7f4b"
    speck_sched = Speck128KeySchedule(speck_test_key)
    speck_test_ct = speck128_128_encrypt(speck_test_pt, speck_sched)
    print(f"SPECK Test CT: {bytes_to_hex_string(speck_test_ct)} (Esperado: {speck_test_expected_ct_hex})")
    assert bytes_to_hex_string(speck_test_ct) == speck_test_expected_ct_hex, "Falha no Test Vector do SPECK!"
    print("SPECK Test Vector: OK")
    # Teste RECTANGLE
    rect_test_key = bytes.fromhex("00000000000000000000000000000000")
    rect_test_pt = bytes.fromhex("0000000000000000")
    rect_test_expected_ct_hex = "28cd663087542029"
    rect_sched = RectangleKeySchedule(rect_test_key)
    rect_test_ct = rectangle_encrypt_block(rect_test_pt, rect_sched)
    print(f"RECTANGLE Test CT: {bytes_to_hex_string(rect_test_ct)} (Esperado: {rect_test_expected_ct_hex})")
    assert bytes_to_hex_string(rect_test_ct) == rect_test_expected_ct_hex, "Falha no Test Vector do RECTANGLE!"
    print("RECTANGLE Test Vector: OK")
    # Teste LwHash
    message_str = "It is clear and self-evident that aims, purposes, instances of wisdom, and benefits can only be followed through choice, will, intention, and volition, not in any other way."
    message_bytes = string_to_bytes(message_str)
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    print("\nLwHash com SPECK:")
    lwhash_speck_128 = LwHash(128, "SPECK", key)
    print(f"  LwHash-SPECK-128: {bytes_to_hex_string(lwhash_speck_128.compute_hash(message_bytes))}")
    lwhash_speck_256 = LwHash(256, "SPECK", key)
    print(f"  LwHash-SPECK-256: {bytes_to_hex_string(lwhash_speck_256.compute_hash(message_bytes))}")
    lwhash_speck_512 = LwHash(512, "SPECK", key)
    print(f"  LwHash-SPECK-512: {bytes_to_hex_string(lwhash_speck_512.compute_hash(message_bytes))}")
    print("\nLwHash-EMLw com RECTANGLE:")
    lwhash_rect_128 = LwHash(128, "RECTANGLE", key)
    print(f"  LwHash-EMLw-128: {bytes_to_hex_string(lwhash_rect_128.compute_hash(message_bytes))}")
    lwhash_rect_256 = LwHash(256, "RECTANGLE", key)
    print(f"  LwHash-EMLw-256: {bytes_to_hex_string(lwhash_rect_256.compute_hash(message_bytes))}")
    lwhash_rect_512 = LwHash(512, "RECTANGLE", key)
    print(f"  LwHash-EMLw-512: {bytes_to_hex_string(lwhash_rect_512.compute_hash(message_bytes))}")