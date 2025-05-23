from utils import rol16, rol32

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
