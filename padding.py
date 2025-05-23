def pad_message(message: bytes, block_size_bytes: int) -> bytes:
    if block_size_bytes == 0:
        raise ValueError("Tamanho do bloco não pode ser zero.")
    padded_message = bytearray(message)
    padded_message.append(0x80)
    current_len_bytes = len(padded_message)
    bytes_to_add = (block_size_bytes - (current_len_bytes % block_size_bytes)) % block_size_bytes
    padded_message.extend(b'\x00' * bytes_to_add)
    return bytes(padded_message)
