#include <iostream>
#include <vector>
#include <string>
#include "lwhash_core.hpp"
#include "utils.hpp" // Para string_to_bytes e bytes_to_hex_string

void print_hash(const std::string& algo_name, const std::vector<uint8_t>& hash_val) {
    std::cout << algo_name << " Hash: " << bytes_to_hex_string(hash_val) << std::endl;
}

int main() {
    std::string message_str = "Hello, LwHash!";
    std::vector<uint8_t> message_bytes = string_to_bytes(message_str);

    // Chave de 128 bits (16 bytes) - exemplo
    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    try {
        // Teste LwHash com SPECK (original)
        LwHash lwhash_speck(256, CipherChoice::SPECK_CIPHER, key); // Saída de 256 bits
        std::vector<uint8_t> hash_speck = lwhash_speck.compute_hash(message_bytes);
        print_hash("LwHash-SPECK (256)", hash_speck);

        LwHash lwhash_speck_128(128, CipherChoice::SPECK_CIPHER, key); // Saída de 128 bits
        std::vector<uint8_t> hash_speck_128 = lwhash_speck_128.compute_hash(message_bytes);
        print_hash("LwHash-SPECK (128)", hash_speck_128);

        LwHash lwhash_speck_512(512, CipherChoice::SPECK_CIPHER, key); // Saída de 512 bits
        std::vector<uint8_t> hash_speck_512 = lwhash_speck_512.compute_hash(message_bytes);
        print_hash("LwHash-SPECK (512)", hash_speck_512);


        // Teste LwHash-EMLw com RECTANGLE
        LwHash lwhash_emlw(256, CipherChoice::RECTANGLE_CIPHER, key); // Saída de 256 bits
        std::vector<uint8_t> hash_emlw = lwhash_emlw.compute_hash(message_bytes);
        print_hash("LwHash-EMLw (256)", hash_emlw);

        LwHash lwhash_emlw_128(128, CipherChoice::RECTANGLE_CIPHER, key); // Saída de 128 bits
        std::vector<uint8_t> hash_emlw_128 = lwhash_emlw_128.compute_hash(message_bytes);
        print_hash("LwHash-EMLw (128)", hash_emlw_128);
        
        LwHash lwhash_emlw_512(512, CipherChoice::RECTANGLE_CIPHER, key); // Saída de 512 bits
        std::vector<uint8_t> hash_emlw_512 = lwhash_emlw_512.compute_hash(message_bytes);
        print_hash("LwHash-EMLw (512)", hash_emlw_512);


    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}