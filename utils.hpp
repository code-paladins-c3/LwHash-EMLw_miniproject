// utils.hpp
#ifndef UTILS_HPP
#define UTILS_HPP

#include <vector>
#include <cstdint>
#include <string>

// Converte string para vetor de bytes
std::vector<uint8_t> string_to_bytes(const std::string& str);

// Converte vetor de bytes para string hexadecimal
std::string bytes_to_hex_string(const std::vector<uint8_t>& bytes);

// Operação XOR em vetores de bytes do mesmo tamanho
std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& vec1, const std::vector<uint8_t>& vec2);

// Funções de rotação para uint64_t (necessárias para SPECK e RECTANGLE)
uint64_t rotr64(uint64_t x, int n);
uint64_t rotl64(uint64_t x, int n);

// Outras funções utilitárias que possam ser necessárias

#endif // UTILS_HPP