#include "padding.hpp"
#include <stdexcept> // Para std::runtime_error

std::vector<uint8_t> pad_message(const std::vector<uint8_t>& message, size_t block_size_bytes) {
    if (block_size_bytes == 0) {
        throw std::runtime_error("Block size cannot be zero.");
    }
    std::vector<uint8_t> padded_message = message;
    size_t message_len_bytes = message.size();
    size_t p = message_len_bytes % block_size_bytes; // Modulo B (originalmente P = mod B, P é o resto)

    // O algoritmo no paper parece um pouco confuso na descrição de 'd'.
    // "d = P - 1" se P é o resto, e M^d = M || 1x || 0^d
    // Se P é o número de bytes que faltam para completar o bloco, então P = (block_size_bytes - (message_len_bytes % block_size_bytes)) % block_size_bytes
    // Se message_len_bytes % block_size_bytes == 0, então precisamos de um bloco inteiro de padding.
    // Vamos seguir a lógica mais comum: adicionar '1' seguido de '0's até o tamanho ser múltiplo de block_size_bytes.
    // E se já for múltiplo, adicionar um bloco inteiro de padding.

    padded_message.push_back(0x80); // Adiciona o bit '1' (10000000 em binário)

    size_t current_len_bytes = padded_message.size();
    size_t bytes_to_add = (block_size_bytes - (current_len_bytes % block_size_bytes)) % block_size_bytes;

    for (size_t i = 0; i < bytes_to_add; ++i) {
        padded_message.push_back(0x00);
    }
    return padded_message;
}