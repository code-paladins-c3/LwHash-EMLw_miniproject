from utils import xor_bytes

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
