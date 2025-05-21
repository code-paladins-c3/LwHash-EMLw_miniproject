// rectangle.hpp
#ifndef RECTANGLE_HPP
#define RECTANGLE_HPP

#include <vector>
#include <cstdint>

// RECTANGLE (bloco de 64 bits, chave de 128 bits) como exemplo
const size_t RECTANGLE_BLOCK_SIZE_BYTES = 8;  // 64 bits
const size_t RECTANGLE_KEY_SIZE_BYTES = 16; // 128 bits (pode ser 80 bits também)
const int RECTANGLE_ROUNDS = 25; // Conforme especificação

// Função de expansão de chave para RECTANGLE
std::vector<uint16_t> rectangle_key_schedule(const std::vector<uint8_t>& master_key); // Exemplo, a chave do RECTANGLE é usada de forma diferente

// Função de cifragem RECTANGLE
// Input: plaintext_block (64 bits), round_keys
// Output: ciphertext_block (64 bits)
std::vector<uint8_t> rectangle_encrypt(const std::vector<uint8_t>& plaintext_block, const std::vector<uint16_t>& round_keys); // Exemplo

#endif // RECTANGLE_HPP