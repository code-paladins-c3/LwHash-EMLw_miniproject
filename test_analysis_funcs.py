from lwhash import LwHash
from utils import string_to_bytes
from hash_analysis import analyze_bit_distribution, analyze_byte_distribution, generate_hash_bitstream, generate_list_of_hashes

if __name__ == "__main__":
    # Teste de analyze_byte_distribution
    print("Testando analyze_byte_distribution...")
    lwhash = LwHash(256, "SPECK", bytes.fromhex("00112233445566778899aabbccddeeff"))
    hashes = generate_list_of_hashes(lwhash, num_hashes=100)
    analyze_byte_distribution(hashes, outdir="resultados", filename="byte_dist_custom_test.png")
    print("byte_dist_custom_test.png gerado em 'resultados/'.")

    # Teste de analyze_bit_distribution
    print("Testando analyze_bit_distribution...")
    bitstream = generate_hash_bitstream(lwhash, num_hashes=100)
    analyze_bit_distribution(bitstream, outdir="resultados", filename="bit_zeros_uns_test.png")
    print("bit_zeros_uns_test.png gerado em 'resultados/'.")
