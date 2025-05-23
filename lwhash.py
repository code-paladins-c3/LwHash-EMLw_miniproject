from utils import xor_bytes, bytes_to_hex_string, string_to_bytes
from speck128 import Speck128KeySchedule, speck128_128_encrypt
from rectangle128 import RectangleKeySchedule, rectangle_encrypt_128bit_wrapper
from ctr_mode import ctr_mode_encrypt
from padding import pad_message

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
