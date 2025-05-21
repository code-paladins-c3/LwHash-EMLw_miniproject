#include "lwhash_core.hpp"
#include "padding.hpp"
#include "utils.hpp"
#include "speck.hpp"      // Para funções reais do SPECK
#include "rectangle.hpp"  // Para funções reais do RECTANGLE
#include "ctr_mode.hpp"   // Para ctr_mode_encrypt
#include <stdexcept>
#include <iostream> // Para debug

// Funções placeholder para as cifras reais - SUBSTITUIR PELAS REAIS
std::vector<uint8_t> placeholder_speck_encrypt_for_lwhash(const std::vector<uint8_t>& plaintext_block, const void* round_keys) {
    // Chamar speck_encrypt real aqui
    if (plaintext_block.size() != SPECK_BLOCK_SIZE_BYTES) throw std::runtime_error("SPECK: Invalid block size for LwHash internal encryption");
    const auto* rk = static_cast<const std::vector<uint64_t>*>(round_keys);
    // std::cout << "Debug: SPECK encrypt placeholder called.\n";
    // return speck_encrypt(plaintext_block, *rk); // CHAMADA REAL
    return std::vector<uint8_t>(plaintext_block.size(), 0xAA); // Placeholder
}

std::vector<uint8_t> LwHash::rectangle_encrypt_128bit_wrapper(const std::vector<uint8_t>& block128, const void* round_keys_ptr_cast) {
    if (block128.size() != 16) throw std::runtime_error("RECTANGLE Wrapper: Input block must be 128 bits.");

    const auto* rk = static_cast<const std::vector<uint16_t>*>(round_keys_ptr_cast);

    std::vector<uint8_t> left_half_64(block128.begin(), block128.begin() + 8);
    std::vector<uint8_t> right_half_64(block128.begin() + 8, block128.end());

    // std::cout << "Debug: RECTANGLE encrypt placeholder for LwHash (left half) called.\n";
    
    std::vector<uint8_t> encrypted_right = rectangle_encrypt(right_half_64, *rk); // CHAMADA REAL

    // Corrigido: concatenar corretamente os blocos cifrados
    std::vector<uint8_t> encrypted_128;
    encrypted_128.reserve(16);
    encrypted_128.insert(encrypted_128.end(), encrypted_left.begin(), encrypted_left.end());
    encrypted_128.insert(encrypted_128.end(), encrypted_right.begin(), encrypted_right.end());
    return encrypted_128;
}


LwHash::LwHash(size_t output_bit_len, CipherChoice cipher, const std::vector<uint8_t>& key)
    : selected_cipher(cipher), master_key(key), p_round_keys(nullptr) {
    if (output_bit_len != 128 && output_bit_len != 256 && output_bit_len != 512) {
        throw std::runtime_error("Unsupported hash output length. Must be 128, 256, or 512 bits.");
    }
    output_len_bytes = output_bit_len / 8;

    // Determina internal_digest_size_bytes baseado no paper.
    // O Algoritmo 2 sugere que a mensagem é dividida em blocos M_i de "digest size". [cite: 226]
    // E cada M_i é particionado em sub-blocos de 128 bits. [cite: 227]
    // O "digest size" do paper parece ser o tamanho do bloco de mensagem que o LwHash processa por iteração principal.
    // Se o output_len é 128, o digest_size do Algoritmo 2 é 128. Se 256, é 256. Se 512, é 512.
    internal_digest_size_bytes = output_len_bytes; // Esta é uma interpretação, verificar!
                                                   // O paper diz: "message is divided into digest sizes, which can be 512-bit, 256-bit, or 128-bit" [cite: 226]
                                                   // E "number of sub-blocks formed varies according to the digest size." [cite: 228]
                                                   // "If the digest size is 512-bit, four sub-blocks are created..." [cite: 229]
                                                   // Isso confirma que internal_digest_size_bytes = 64 para 512-bit digest, 32 para 256, 16 para 128.
                                                   // Cada sub-bloco é de 128 bits (16 bytes).

    if (internal_digest_size_bytes == 64) num_sub_blocks = 4;       // 512 bit digest
    else if (internal_digest_size_bytes == 32) num_sub_blocks = 2;  // 256 bit digest
    else if (internal_digest_size_bytes == 16) num_sub_blocks = 1;  // 128 bit digest
    else throw std::runtime_error("Internal logic error for digest size.");


    initialize_cipher_params();
}

void LwHash::initialize_cipher_params() {
    // O LwHash usa sub-blocos de 128 bits para a cifragem interna [cite: 196, 227]
    // A chave é de 128 bits para SPECK conforme exemplo do paper (Figura 2 usa Key) e Seção 4.5.3 [cite: 336]
    if (master_key.size() != 16) { // 128-bit key
        throw std::runtime_error("Master key must be 128 bits (16 bytes).");
    }

    if (selected_cipher == CipherChoice::SPECK_CIPHER) {
        // Para SPECK com blocos de 128 bits (2 palavras de 64 bits), 32 rounds [cite: 217]
        speck_round_keys_storage = speck_key_schedule(master_key, 32); // 32 rounds
        p_round_keys = &speck_round_keys_storage;
        current_encrypt_func = placeholder_speck_encrypt_for_lwhash; // Usar a real
        current_cipher_block_size_bytes = SPECK_BLOCK_SIZE_BYTES; // 16 bytes (128 bits)
    } else { // RECTANGLE_CIPHER
        rectangle_round_keys_storage = rectangle_key_schedule(master_key); // RECTANGLE usa chave de 128 bits
        p_round_keys = &rectangle_round_keys_storage;
        current_encrypt_func = [this](const std::vector<uint8_t>& block, const void* rk_ptr) {
            return this->rectangle_encrypt_128bit_wrapper(block, rk_ptr);
        };
        current_cipher_block_size_bytes = 16; // LwHash opera em sub-blocos de 128 bits internamente
    }
}

// Esta função é chamada pelo modo CTR. Ela aplica a cifra de bloco (SPECK ou RECTANGLE_wrapper)
// ao nonce (que aqui é o 'block_data' vindo do CTR).
std::vector<uint8_t> LwHash::encrypt_block_for_lwhash(const std::vector<uint8_t>& block_data, const std::vector<uint8_t>& nonce_val /* não usado diretamente aqui se CTR já lida com nonce*/) {
    // O `nonce_val` do Algoritmo 2 parece ser o contador para o modo CTR.
    // `Encrypt(Nonce++, RK)` [cite: 234]
    // A função `current_encrypt_func` já deve ser a cifragem do bloco (ex: SPECK(nonce, RK))
    // O modo CTR já faz Encrypt(Nonce++, RK) XOR Plaintext_sub_block.
    // Aqui, o `block_data` no Algoritmo 2 (Ciphertext_j = Encrypt(Nonce++, RK) XOR m_j)
    // O `Encrypt(Nonce++, RK)` é o keystream.
    // Então, esta função wrapper deve ser chamada pelo CTR como a `encrypt_func`.
    // O `block_data` que chega aqui do CTR é o `counter_block` (Nonce++).
    return current_encrypt_func(block_data, p_round_keys);
}


// Processa um bloco de mensagem de tamanho `internal_digest_size_bytes`
// Conforme a lógica interna da Figura 1 do paper (operações dentro de um "Block_i")
std::vector<uint8_t> LwHash::process_message_block(const std::vector<uint8_t>& message_k_block) {
    if (message_k_block.size() != internal_digest_size_bytes) {
        throw std::runtime_error("Invalid message k_block size for LwHash processing.");
    }

    std::vector<std::vector<uint8_t>> M_sub_blocks(num_sub_blocks, std::vector<uint8_t>(current_cipher_block_size_bytes));
    std::vector<std::vector<uint8_t>> eM_sub_blocks(num_sub_blocks, std::vector<uint8_t>(current_cipher_block_size_bytes));

    // 1. Dividir message_k_block em M_sub_blocks (m_j no Algoritmo 2)
    // Cada sub-bloco tem `current_cipher_block_size_bytes` (128 bits)
    for (size_t j = 0; j < num_sub_blocks; ++j) {
        std::copy(message_k_block.begin() + j * current_cipher_block_size_bytes,
                  message_k_block.begin() + (j + 1) * current_cipher_block_size_bytes,
                  M_sub_blocks[j].begin());
    }

    // Gerar Nonce inicial para este message_k_block (deve ser único ou bem gerenciado)
    // O paper não especifica a origem do Nonce no Algoritmo 2, apenas "Nonce++".
    // Vamos usar um nonce fixo para demonstração, mas isso precisa de cuidado na prática.
    std::vector<uint8_t> current_nonce(current_cipher_block_size_bytes, 0x00);
    // Um IV/nonce deveria ser parte da inicialização ou derivado da chave/mensagem.
    // Para simplicidade, vamos usar um nonce que é reiniciado para cada `message_k_block` e incrementado internamente pelo CTR.
    // Ou, o nonce é global e continua incrementando. Seção 3, Figura 2 sugere um nonce inicial "520c36fa..."
    // Vamos assumir um nonce inicial para a função de hash inteira, e o CTR mode o incrementa.
    // A variável `current_nonce` aqui seria o estado do contador para o modo CTR.

    // 2. Cifrar cada sub-bloco M_j usando modo CTR (Algoritmo 2, primeiro loop aninhado) [cite: 234]
    // Ciphertext_j = Encrypt(Nonce_j, RK) ^ M_j
    // Onde Encrypt(Nonce_j, RK) é o keystream gerado pelo CTR.
    // A função ctr_mode_encrypt faz exatamente isso.
    // O "Nonce++" do Algoritmo 2 [cite: 234] é tratado dentro do `ctr_mode_encrypt`.
    // E a função `this->encrypt_block_for_lwhash` é a `encrypt_func` para o CTR.
    // Ela cifra o valor do contador (`counter_block` dentro do `ctr_mode_encrypt`).

    std::vector<uint8_t> nonce_for_ctr_sub_blocks(current_cipher_block_size_bytes, 0x1A); // Exemplo de Nonce inicial para este estágio

    for (size_t j = 0; j < num_sub_blocks; ++j) {
        eM_sub_blocks[j] = ctr_mode_encrypt(M_sub_blocks[j], nonce_for_ctr_sub_blocks, p_round_keys,
                                           [this](const std::vector<uint8_t>& blk, const void* rk) {
                                               return this->current_encrypt_func(blk, rk); // Cifra o contador
                                           },
                                           current_cipher_block_size_bytes);
        // O nonce_for_ctr_sub_blocks precisa ser incrementado aqui para o próximo sub-bloco M_{j+1}
        // se o CTR não o fizer globalmente ou se quisermos um stream de chaves diferente para cada M_j.
        // No entanto, o CTR mode já incrementa seu contador interno. Se M_sub_blocks fossem concatenados
        // e passados de uma vez para o CTR, isso seria automático.
        // Como são processados separadamente, o `nonce_for_ctr_sub_blocks` deve ser o mesmo para
        // que o CTR gere keystream_0, keystream_1, etc. para M_0, M_1.
        // Alternativamente, cada `eM_sub_blocks[j] = Encrypt(Nonce_j, RK) ^ M_sub_blocks[j]`
        // O `Encrypt` é `current_encrypt_func(nonce_val_para_j, p_round_keys)`.
        // Esta é a parte mais confusa do Algoritmo 2.
        // Reinterpretando: o primeiro loop do Algoritmo 2 é:
        // for j = 0 to r: Ciphertext_j = Encrypt(Nonce++, RK) XOR m_j [cite: 234]
        // Isto é exatamente o modo CTR aplicado à concatenação de todos os m_j.
        // Vamos simplificar: concatenar M_sub_blocks e aplicar CTR uma vez.

        // Vamos seguir a estrutura do paper que parece cifrar cada m_j independentemente com Nonce++
        // Este é o keystream_j = current_encrypt_func(nonce_for_ctr_sub_blocks, p_round_keys);
        // eM_sub_blocks[j] = xor_bytes(M_sub_blocks[j], keystream_j);
        // increment_nonce(nonce_for_ctr_sub_blocks); // Manter o estado do Nonce++
        // A função ctr_mode_encrypt já faz isso se passarmos M_sub_blocks[j] como 'data'.
        // Se passarmos todo o message_k_block para o CTR, ele já cuida da divisão e XOR.
    }
    // Abordagem mais simples: o `message_k_block` é o conjunto de `m_j` concatenados.
    // O CTR mode irá processá-lo.
    std::vector<uint8_t> concatenated_M_sub_blocks;
    for(const auto& sub_block : M_sub_blocks) {
        concatenated_M_sub_blocks.insert(concatenated_M_sub_blocks.end(), sub_block.begin(), sub_block.end());
    }
    // `nonce_for_ctr_sub_blocks` é o IV para o CTR.
    std::vector<uint8_t> concatenated_eM_sub_blocks = ctr_mode_encrypt(concatenated_M_sub_blocks, nonce_for_ctr_sub_blocks, p_round_keys,
                                                                        [this](const std::vector<uint8_t>& blk, const void* rk) {
                                                                            return this->current_encrypt_func(blk, rk);
                                                                        },
                                                                        current_cipher_block_size_bytes);

    for (size_t j = 0; j < num_sub_blocks; ++j) {
        std::copy(concatenated_eM_sub_blocks.begin() + j * current_cipher_block_size_bytes,
                  concatenated_eM_sub_blocks.begin() + (j + 1) * current_cipher_block_size_bytes,
                  eM_sub_blocks[j].begin());
    }


    // 3. Calcular Block_minihash (Algoritmo 2, segundo loop) [cite: 235]
    // Block_minihash_temp = eM_sub_blocks[0]
    // for j = 1 to r: Block_minihash_temp = Block_minihash_temp XOR eM_sub_blocks[j]
    std::vector<uint8_t> block_minihash_temp = eM_sub_blocks[0];
    for (size_t j = 1; j < num_sub_blocks; ++j) {
        block_minihash_temp = xor_bytes(block_minihash_temp, eM_sub_blocks[j]);
    }
    // Block_minihash = Encrypt(Block_minihash_temp, RK) [cite: 235]
    // Esta cifragem NÃO é em modo CTR. É uma cifragem de bloco direta.
    // O `current_encrypt_func` espera (bloco, chaves_rodada).
    std::vector<uint8_t> block_minihash = current_encrypt_func(block_minihash_temp, p_round_keys);


    // 4. Atualizar eM_sub_blocks (Algoritmo 2, terceiro loop) [cite: 235]
    // Ciphertext_j = Ciphertext_j XOR Block_minihash  (onde Ciphertext_j é eM_sub_blocks[j])
    for (size_t j = 0; j < num_sub_blocks; ++j) {
        eM_sub_blocks[j] = xor_bytes(eM_sub_blocks[j], block_minihash);
    }

    // 5. Combinar os eM_sub_blocks atualizados para formar a saída deste process_message_block (Block_i na Figura 1)
    // A Figura 1 mostra XOR e Adição para combinar os W_j (que são os eM_sub_blocks[j] atualizados).
    // O Algoritmo 2, no último loop, acumula em `Hash_i`.
    // "if i mod 2 == 0 then Hash_i = Hash_i + Ciphertext_j else Hash_i = Hash_i XOR Ciphertext_j" [cite: 235]
    // Esta parte é para combinar os *resultados dos `process_message_block`*, não os sub-blocos internos.
    // A saída de `process_message_block` é a concatenação dos `eM_sub_blocks[j]` atualizados.
    std::vector<uint8_t> processed_block_output;
    for (size_t j = 0; j < num_sub_blocks; ++j) {
        processed_block_output.insert(processed_block_output.end(), eM_sub_blocks[j].begin(), eM_sub_blocks[j].end());
    }
    return processed_block_output; // Este é o "Block_i" da Figura 1.
}


std::vector<uint8_t> LwHash::compute_hash(const std::vector<uint8_t>& message) {
    // 1. Padding
    // O LwHash opera em "digest sizes" de 128, 256 ou 512 bits. [cite: 226]
    // O padding deve levar a mensagem a um múltiplo de `internal_digest_size_bytes`.
    std::vector<uint8_t> padded_message = pad_message(message, internal_digest_size_bytes);

    size_t num_message_k_blocks = padded_message.size() / internal_digest_size_bytes;
    std::vector<std::vector<uint8_t>> H_blocks(num_message_k_blocks, std::vector<uint8_t>(internal_digest_size_bytes));

    // 2. Processar cada bloco principal da mensagem (M_i no Algoritmo 2, que são os "digest size" blocks)
    for (size_t i = 0; i < num_message_k_blocks; ++i) {
        std::vector<uint8_t> current_k_block(internal_digest_size_bytes);
        std::copy(padded_message.begin() + i * internal_digest_size_bytes,
                  padded_message.begin() + (i + 1) * internal_digest_size_bytes,
                  current_k_block.begin());
        H_blocks[i] = process_message_block(current_k_block); // H_blocks[i] é o "Block_i" da Figura 1
    }

    // 3. Combinar os H_blocks (Block_i) para produzir o hash final (conforme Figura 1 e último loop do Algoritmo 2)
    // O Algoritmo 2 do paper tem um loop final:
    // for i = 0 to t (num_message_k_blocks - 1)
    //   for j = 0 to r (num_sub_blocks - 1)
    //     if i mod 2 == 0 then Hash_final_acumulado = Hash_final_acumulado + Ciphertext_ij
    //     else Hash_final_acumulado = Hash_final_acumulado XOR Ciphertext_ij
    // Onde Ciphertext_ij são os componentes do H_blocks[i].
    // E `Hash_final_acumulado` é do tamanho `output_len_bytes`.
    // Isso é complexo. A Figura 1 é mais clara: os "Block_i" (saídas de `process_message_block`) são XORados e Adicionados.
    // "Addition and XOR operations are applied to ciphertext blocks (Block_i) successively to shuffle and compression." [cite: 204]

    // Vamos seguir a Figura 1:
    // HashOutput = Block_0 (op) Block_1 (op) Block_2 ...
    // Onde (op) alterna entre + e XOR, ou é sempre XOR?
    // A Figura 1 mostra um + entre Block0 e Block1, depois um XOR com Block2, etc.
    // Isso é incomum. Mais comum é um XOR contínuo ou uma compressão mais complexa.
    // O último loop do Algoritmo 2 é mais explícito:
    // `Hash_i` no Algoritmo 2 parece ser o hash final sendo construído.
    // E `Ciphertext_j` no último loop se refere aos componentes de `H_blocks[i]`.
    // Isso significa que o hash final é do tamanho de UM sub-bloco (128 bits)? Não, `output_len_bytes`.

    // Reinterpretação do último loop do Algoritmo 2 (Assumindo que `Hash_i` é o acumulador do hash final):
    // `Hash` (acumulador final) deve ter `output_len_bytes`.
    // `H_blocks[i]` (que é o `Block_i` da Figura 1) tem `internal_digest_size_bytes`.
    // Se `output_len_bytes` != `internal_digest_size_bytes`, como alinhar?
    // Geralmente o `output_len_bytes` é o mesmo que o `internal_digest_size_bytes` ou menor.
    // No LwHash, eles são iguais.

    std::vector<uint8_t> final_hash_value(output_len_bytes, 0x00); // Inicializa com zeros

    if (num_message_k_blocks > 0) {
        final_hash_value = H_blocks[0]; // Começa com o primeiro H_block processado
        for (size_t i = 1; i < num_message_k_blocks; ++i) {
            // A Figura 1 mostra alternância, o texto diz "Addition and XOR operations are applied... successively" [cite: 204]
            // O Algoritmo 2, último loop, parece mais sobre construir cada `Hash_i` (que são os H_blocks[i])
            // e não sobre combinar os `Hash_i` entre si.
            // "for i=0 to t do ... Hashi = ... end for" -> produz H_blocks[0]...H_blocks[t]
            // Não há um passo explícito no Algoritmo 2 para combinar os `H_blocks[i]` para formar o hash final.
            // A Figura 1 é a única pista: Block0 + Block1 XOR Block2 + Block3 ...
            // Esta é uma parte que precisa de clarificação ou uma decisão de design.

            // Assumindo um XOR simples entre os H_blocks[i] (Block_i da Figura 1) como compressão final comum:
            final_hash_value = xor_bytes(final_hash_value, H_blocks[i]);
        }
    }
    // Se o output_len_bytes for menor que o internal_digest_size_bytes (não é o caso aqui),
    // um truncamento seria necessário.

    return final_hash_value;
}