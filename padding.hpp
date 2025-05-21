#ifndef PADDING_HPP
#define PADDING_HPP

#include <vector>
#include <cstdint>

// Input: Message (M), Block Size (B) em bytes
// Output: Padded Message (Md)
std::vector<uint8_t> pad_message(const std::vector<uint8_t>& message, size_t block_size_bytes);

#endif // PADDING_HPP