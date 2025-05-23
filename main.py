from utils import bytes_to_hex_string, string_to_bytes
# Certifique-se que os nomes importados correspondem aos nomes das classes/funções
# nos seus arquivos speck128.py e rectangle128.py.
# Vou assumir que rectangle128.py contém a versão "oficial" do RECTANGLE
# que você forneceu anteriormente.
from speck128 import Speck128KeySchedule, speck128_128_encrypt
from rectangle128 import RectangleKeySchedule as RectangleOfficialKeySchedule, \
                           rectangle_encrypt_block as rectangle_official_encrypt_block
from lwhash import LwHash
from hash_analysis import HashByteDistribution, HashBitDistribution, AvalancheEffectTest

if __name__ == "__main__":
    # Seus testes existentes:
    print("--- Testes Personalizados LwHash ---")
    # Teste LwHash com mensagem curta
    print("\nTeste LwHash com mensagem curta:")
    msg_curta = b"abc"
    key_curta = bytes.fromhex("00112233445566778899aabbccddeeff")
    for bits in [128, 256, 512]:
        h_speck = LwHash(bits, "SPECK", key_curta).compute_hash(msg_curta)
        print(f"  SPECK-{bits} (msg: 'abc'): {bytes_to_hex_string(h_speck)}")
        h_rect = LwHash(bits, "RECTANGLE", key_curta).compute_hash(msg_curta)
        print(f"  RECTANGLE-{bits} (msg: 'abc'): {bytes_to_hex_string(h_rect)}")

    # Teste LwHash com mensagem vazia
    print("\nTeste LwHash com mensagem vazia:")
    msg_vazia = b""
    for bits in [128, 256, 512]:
        h_speck = LwHash(bits, "SPECK", key_curta).compute_hash(msg_vazia)
        print(f"  SPECK-{bits} (msg: ''): {bytes_to_hex_string(h_speck)}")
        h_rect = LwHash(bits, "RECTANGLE", key_curta).compute_hash(msg_vazia)
        print(f"  RECTANGLE-{bits} (msg: ''): {bytes_to_hex_string(h_rect)}")

    # Teste LwHash com mensagem longa
    print("\nTeste LwHash com mensagem longa:")
    msg_longa = b"A" * 1000
    for bits in [128, 256, 512]:
        h_speck = LwHash(bits, "SPECK", key_curta).compute_hash(msg_longa)
        print(f"  SPECK-{bits} (msg: 'A'*1000): {bytes_to_hex_string(h_speck)}")
        h_rect = LwHash(bits, "RECTANGLE", key_curta).compute_hash(msg_longa)
        print(f"  RECTANGLE-{bits} (msg: 'A'*1000): {bytes_to_hex_string(h_rect)}")

    # Teste LwHash sensibilidade a 1 bit
    print("\nTeste de sensibilidade a 1 bit:")
    msg1_sens = b"mensagem de teste"
    msg2_sens = bytearray(msg1_sens)
    if len(msg2_sens) > 0: # Adicionado para evitar erro com string vazia
        msg2_sens[0] ^= 0x01
    else:
        msg2_sens = b"\x01" # Caso a msg1_sens seja vazia, cria uma msg2 diferente

    for bits_sens in [256]: # Renomeado para evitar conflito com a var 'bits' anterior
        h1_speck = LwHash(bits_sens, "SPECK", key_curta).compute_hash(msg1_sens)
        h2_speck = LwHash(bits_sens, "SPECK", key_curta).compute_hash(bytes(msg2_sens))
        print(f"  SPECK-{bits_sens} original:    {bytes_to_hex_string(h1_speck)}")
        print(f"  SPECK-{bits_sens} alterada:    {bytes_to_hex_string(h2_speck)}")
        diff_speck = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(h1_speck, h2_speck))
        print(f"    Bits diferentes: {diff_speck} de {bits_sens}")

        h1_rect = LwHash(bits_sens, "RECTANGLE", key_curta).compute_hash(msg1_sens)
        h2_rect = LwHash(bits_sens, "RECTANGLE", key_curta).compute_hash(bytes(msg2_sens))
        print(f"  RECTANGLE-{bits_sens} original:  {bytes_to_hex_string(h1_rect)}")
        print(f"  RECTANGLE-{bits_sens} alterada:  {bytes_to_hex_string(h2_rect)}")
        diff_rect = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(h1_rect, h2_rect))
        print(f"    Bits diferentes: {diff_rect} de {bits_sens}")
    
    print("\n" + "="*50)
    print("--- Testes de Comparação com o Artigo LwHash ---")
    print("="*50)

    # Chave de 128 bits (16 bytes) - todos zeros para os testes do paper
    zero_key = bytes.fromhex("00000000000000000000000000000000")

    # Condição 1: LwHash-SPECK-256
    print("\nCondição 1 do Paper: LwHash-SPECK-256")
    msg_cond1_str = "LwHash is a lightweight cryptographic hash function."
    msg_cond1_bytes = string_to_bytes(msg_cond1_str)
    expected_hash_cond1 = "4e0f4d7a83eb45f7bdaec9ec8c91289cdbc7fd9f2ca046ca0021bcbbc017b3fe"

    try:
        lwhash_speck_cond1 = LwHash(output_bit_len=256, cipher_choice="SPECK", key_bytes=zero_key)
        hash_speck_cond1_calc = lwhash_speck_cond1.compute_hash(msg_cond1_bytes)
        
        print(f"  Mensagem: \"{msg_cond1_str}\"")
        print(f"  Chave   : {bytes_to_hex_string(zero_key)}")
        print(f"  Calculado: {bytes_to_hex_string(hash_speck_cond1_calc)}")
        print(f"  Esperado : {expected_hash_cond1}")
        if bytes_to_hex_string(hash_speck_cond1_calc) == expected_hash_cond1:
            print("  Resultado: CORRESPONDE AO ARTIGO ✅")
        else:
            print("  Resultado: NÃO CORRESPONDE AO ARTIGO ❌")
    except Exception as e:
        print(f"  Erro na Condição 1: {e}")

    # Condição 2: LwHash-EMLw-RECTANGLE-256
    print("\nCondição 2 do Paper: LwHash-EMLw-RECTANGLE-256")
    msg_cond2_str = "LwHash-EMLw is an enhanced version of LwHash."
    msg_cond2_bytes = string_to_bytes(msg_cond2_str)
    expected_hash_cond2 = "857690de0f71b68817916e44524a381782e78f54a1d27609a077891ab460f696"

    try:
        # Certifique-se que a string "RECTANGLE" aqui corresponda à
        # inicialização da versão "oficial" do RECTANGLE na sua classe LwHash
        lwhash_emlw_cond2 = LwHash(output_bit_len=256, cipher_choice="RECTANGLE", key_bytes=zero_key)
        hash_emlw_cond2_calc = lwhash_emlw_cond2.compute_hash(msg_cond2_bytes)

        print(f"  Mensagem: \"{msg_cond2_str}\"")
        print(f"  Chave   : {bytes_to_hex_string(zero_key)}")
        print(f"  Calculado: {bytes_to_hex_string(hash_emlw_cond2_calc)}")
        print(f"  Esperado : {expected_hash_cond2}")
        if bytes_to_hex_string(hash_emlw_cond2_calc) == expected_hash_cond2:
            print("  Resultado: CORRESPONDE AO ARTIGO ✅")
        else:
            print("  Resultado: NÃO CORRESPONDE AO ARTIGO ❌")
            print("    (Nota: Verifique se a implementação de RECTANGLE em 'rectangle128.py' e sua integração em 'lwhash.py' estão alinhadas com a versão usada para gerar o vetor de teste do paper.)")
    except Exception as e:
        print(f"  Erro na Condição 2: {e}")

    # Análise Estatística dos Resultados
    print("\n" + "="*50)
    print("Análise Estatística dos Resultados de Avalanche e Distribuição")
    print("="*50)

    import random
    def random_bytes(n):
        return bytes(random.getrandbits(8) for _ in range(n))

    def bit_diff(b1: bytes, b2: bytes) -> int:
        return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))

    # Parâmetros do teste
    N = 100  # número de amostras
    msg_len = 32  # tamanho da mensagem em bytes
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    bits = 256
    print(f"\nTeste de avalanche estatístico (N={N}, {bits} bits, msg_len={msg_len})")
    total_bits = 0
    total_diff_speck = 0
    total_diff_rect = 0
    for i in range(N):
        msg = random_bytes(msg_len)
        msg2 = bytearray(msg)
        bit_idx = random.randint(0, msg_len*8-1)
        byte_idx, bit_in_byte = divmod(bit_idx, 8)
        msg2[byte_idx] ^= (1 << bit_in_byte)
        h1 = LwHash(bits, "SPECK", key).compute_hash(msg)
        h2 = LwHash(bits, "SPECK", key).compute_hash(bytes(msg2))
        diff = bit_diff(h1, h2)
        total_diff_speck += diff
        h1r = LwHash(bits, "RECTANGLE", key).compute_hash(msg)
        h2r = LwHash(bits, "RECTANGLE", key).compute_hash(bytes(msg2))
        diff_r = bit_diff(h1r, h2r)
        total_diff_rect += diff_r
        total_bits += bits
    avg_diff_speck = total_diff_speck / N
    avg_diff_rect = total_diff_rect / N
    print(f"  Avalanche SPECK-256: Média de bits diferentes: {avg_diff_speck:.2f} de {bits} ({(avg_diff_speck/bits)*100:.2f}%)")
    print(f"  Avalanche RECTANGLE-256: Média de bits diferentes: {avg_diff_rect:.2f} de {bits} ({(avg_diff_rect/bits)*100:.2f}%)")

    # Distribuição de bits 0/1 no hash
    print("\nDistribuição de bits 0/1 nos hashes SPECK-256 e RECTANGLE-256:")
    bit_counts_speck = [0]*bits
    bit_counts_rect = [0]*bits
    for i in range(N):
        msg = random_bytes(msg_len)
        h = LwHash(bits, "SPECK", key).compute_hash(msg)
        hr = LwHash(bits, "RECTANGLE", key).compute_hash(msg)
        for j in range(bits):
            if (h[j//8] >> (7-(j%8))) & 1:
                bit_counts_speck[j] += 1
            if (hr[j//8] >> (7-(j%8))) & 1:
                bit_counts_rect[j] += 1
    print(f"  SPECK-256: Média de bits 1 por posição: {sum(bit_counts_speck)/bits/N:.4f}")
    print(f"  RECTANGLE-256: Média de bits 1 por posição: {sum(bit_counts_rect)/bits/N:.4f}")
    print("  (Ideal: próximo de 0.5 para distribuição uniforme)")

    # Geração de hashes aleatórios para análise
    print("\n--- Análise Estatística Detalhada dos Hashes (com gráficos) ---")
    N = 100
    msg_len = 32
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    bits = 256
    # SPECK
    hashes_speck = [LwHash(bits, "SPECK", key).compute_hash(bytes([i%256 for i in range(msg_len)])) for _ in range(N)]
    # RECTANGLE
    hashes_rect = [LwHash(bits, "RECTANGLE", key).compute_hash(bytes([i%256 for i in range(msg_len)])) for _ in range(N)]

    print("\n[SPECK-256]")
    HashByteDistribution(hashes_speck, outdir="resultados").plot(title="Distribuição de Bytes - SPECK-256", filename="byte_dist_speck256.png")
    HashBitDistribution(hashes_speck, outdir="resultados").plot(title="Distribuição de Bits - SPECK-256", filename="bit_dist_speck256.png")
    AvalancheEffectTest(lambda m: LwHash(bits, "SPECK", key).compute_hash(m), msg_len, n_tests=50, outdir="resultados").plot(title="Avalanche - SPECK-256", filename="avalanche_speck256.png")

    print("\n[RECTANGLE-256]")
    HashByteDistribution(hashes_rect, outdir="resultados").plot(title="Distribuição de Bytes - RECTANGLE-256", filename="byte_dist_rectangle256.png")
    HashBitDistribution(hashes_rect, outdir="resultados").plot(title="Distribuição de Bits - RECTANGLE-256", filename="bit_dist_rectangle256.png")
    AvalancheEffectTest(lambda m: LwHash(bits, "RECTANGLE", key).compute_hash(m), msg_len, n_tests=50, outdir="resultados").plot(title="Avalanche - RECTANGLE-256", filename="avalanche_rectangle256.png")
    print("Gráficos salvos na pasta 'resultados/'.")
