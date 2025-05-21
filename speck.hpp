#ifndef SPECK_HPP
#define SPECK_HPP

#include <vector>
#include <cstdint>

// SPECK 128/128 (bloco de 128 bits, chave de 128 bits) como exemplo
// A cifra SPECK no paper opera sobre 2 palavras de 64 bits [cite: 220]
// e o LwHash usa sub-blocos de mensagem de 128 bits [cite: 196]
// A Figura 2 indica 32 rounds [cite: 217]

// Definição da chave e do bloco (exemplo)
const size_t SPECK_BLOCK_SIZE_BYTES = 16; // 128 bits
const size_t SPECK_KEY_SIZE_BYTES = 16;   // 128 bits

// Função de expansão de chave para SPECK
// (Gera as chaves de rodada a partir da chave principal)
// As equações 2 e 3 do paper descrevem a expansão de chave [cite: 222]
std::vector<uint64_t> speck_key_schedule(const std::vector<uint8_t>& master_key, int rounds);

// Função de cifragem SPECK
// Input: plaintext_block (128 bits), round_keys
// Output: ciphertext_block (128 bits)
// O plaintext é dividido em duas palavras de 64 bits x e y [cite: 220]
std::vector<uint8_t> speck_encrypt(const std::vector<uint8_t>& plaintext_block, const std::vector<uint64_t>& round_keys);

// (Opcional: speck_decrypt se necessário para algum teste, embora hash não use)

#endif // SPECK_HPP