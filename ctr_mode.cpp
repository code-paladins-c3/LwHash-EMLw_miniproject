
#include "ctr_mode.hpp"
#include "utils.hpp" // Para xor_bytes
#include <stdexcept>
#include <algorithm> // Para std::min

// Implementação do incremento do nonce (big-endian)
void increment_nonce(std::vector<uint8_t>& nonce) {
    for (int i = nonce.size() - 1; i >= 0; --i) {
        if (nonce[i] < 0xFF) {
            nonce[i]++;
            return;
        }
        nonce[i] = 0x00; // Carry
    }
    // Se chegou aqui, houve overflow em todos os bytes (raro, mas possível)
}

std::vector<uint8_t> ctr_mode_encrypt(
    const std::vector<uint8_t>& data,
    std::vector<uint8_t> nonce, // Passado por valor para modificar localmente, ou passar referência e clonar
    const void* round_keys_ptr,
    block_cipher_func_t encrypt_func,
    size_t cipher_block_size_bytes
) {
    if (nonce.size() != cipher_block_size_bytes) {
        throw std::runtime_error("Nonce size must match cipher block size.");
    }

    std::vector<uint8_t> output_data = data; // Copia os dados de entrada
    std::vector<uint8_t> counter_block = nonce;

    for (size_t i = 0; i < data.size(); i += cipher_block_size_bytes) {
        std::vector<uint8_t> encrypted_counter = encrypt_func(counter_block, round_keys_ptr);

        size_t remaining_bytes = data.size() - i;
        size_t bytes_to_xor = std::min(cipher_block_size_bytes, remaining_bytes);

        for (size_t j = 0; j < bytes_to_xor; ++j) {
            output_data[i + j] = data[i + j] ^ encrypted_counter[j];
        }
        increment_nonce(counter_block);
    }
    return output_data;
}