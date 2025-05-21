#ifndef LWHASH_CORE_HPP
#define LWHASH_CORE_HPP

#include <vector>
#include <cstdint>
#include <string>
#include "ctr_mode.hpp" // Para block_cipher_func_t

enum class CipherChoice { SPECK_CIPHER, RECTANGLE_CIPHER };

class LwHash {
public:
    LwHash(size_t output_bit_len, CipherChoice cipher, const std::vector<uint8_t>& key);

    std::vector<uint8_t> compute_hash(const std::vector<uint8_t>& message);

private:
    size_t output_len_bytes; // Tamanho da saída do hash em bytes
    CipherChoice selected_cipher;
    std::vector<uint8_t> master_key;
    const void* p_round_keys; // Ponteiro para as chaves de rodada (tipo depende da cifra)
    std::vector<uint64_t> speck_round_keys_storage;   // Para guardar as chaves do SPECK
    std::vector<uint16_t> rectangle_round_keys_storage; // Para guardar as chaves do RECTANGLE

    block_cipher_func_t current_encrypt_func;
    size_t current_cipher_block_size_bytes;

    // Parâmetros internos do LwHash
    size_t internal_digest_size_bytes; // 128, 256 ou 512 bits (16, 32, 64 bytes)
    size_t num_sub_blocks; // (internal_digest_size_bytes / cipher_sub_block_processing_size_bytes)
                           // cipher_sub_block_processing_size_bytes é 16 (128 bits) para LwHash com SPECK

    void initialize_cipher_params();
    std::vector<uint8_t> process_message_block(const std::vector<uint8_t>& message_k_block);
    std::vector<uint8_t> encrypt_block_for_lwhash(const std::vector<uint8_t>& block_data, const std::vector<uint8_t>& nonce_val);

    // Para LwHash-EMLw (RECTANGLE)
    std::vector<uint8_t> rectangle_encrypt_128bit_wrapper(const std::vector<uint8_t>& block128, const void* round_keys_ptr_cast);

};

#endif // LWHASH_CORE_HPP