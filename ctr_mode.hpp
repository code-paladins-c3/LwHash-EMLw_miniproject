// ctr_mode.hpp
#ifndef CTR_MODE_HPP
#define CTR_MODE_HPP

#include <vector>
#include <cstdint>
#include <functional> // Para std::function

// Tipo para a função de cifragem de bloco
// Recebe: bloco de plaintext (ou nonce no CTR), chaves de rodada
// Retorna: bloco cifrado
using block_cipher_func_t = std::function<std::vector<uint8_t>(const std::vector<uint8_t>&, const void*)>;
// O `const void*` é para as chaves de rodada, que podem ter tipos diferentes (ex: vector<uint64_t> para SPECK, vector<uint16_t> para RECTANGLE)

// Modo CTR
// Input: data, nonce (IV), round_keys_ptr (ponteiro para as chaves de rodada)
//        encrypt_func (SPECK ou RECTANGLE), block_size_bytes (da cifra)
// Output: resultado da operação XOR com o keystream
std::vector<uint8_t> ctr_mode_encrypt(
    const std::vector<uint8_t>& data,
    std::vector<uint8_t> nonce, // Nonce é modificado (incrementado)
    const void* round_keys_ptr,
    block_cipher_func_t encrypt_func,
    size_t cipher_block_size_bytes
);

#endif // CTR_MODE_HPP