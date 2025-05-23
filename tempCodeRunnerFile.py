 # # Teste RECTANGLE
    # rect_test_key = bytes.fromhex("00000000000000000000000000000000")
    # rect_test_pt = bytes.fromhex("0000000000000000")
    # rect_test_expected_ct_hex = "28cd663087542029"
    # rect_sched = RectangleKeySchedule(rect_test_key)
    # rect_test_ct = rectangle_encrypt_block(rect_test_pt, rect_sched)
    # print(f"RECTANGLE Test CT: {bytes_to_hex_string(rect_test_ct)} (Esperado: {rect_test_expected_ct_hex})")
    # assert bytes_to_hex_string(rect_test_ct) == rect_test_expected_ct_hex, "Falha no Test Vector do RECTANGLE!"
    # print("RECTANGLE Test Vector: OK")
    # # Teste LwHash
    # message_str = "It is clear and self-evident that aims, purposes, instances of wisdom, and benefits can only be followed through choice, will, intention, and volition, not in any other way."
    # message_bytes = string_to_bytes(message_str)
    # key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    # print("\nLwHash com SPECK:")
    # lwhash_speck_128 = LwHash(128, "SPECK", key)
    # print(f"  LwHash-SPECK-128: {bytes_to_hex_string(lwhash_speck_128.compute_hash(message_bytes))}")
    # lwhash_speck_256 = LwHash(256, "SPECK", key)
    # print(f"  LwHash-SPECK-256: {bytes_to_hex_string(lwhash_speck_256.compute_hash(message_bytes))}")
    # lwhash_speck_512 = LwHash(512, "SPECK", key)
    # print(f"  LwHash-SPECK-512: {bytes_to_hex_string(lwhash_speck_512.compute_hash(message_bytes))}")
    # print("\nLwHash-EMLw com RECTANGLE:")
    # lwhash_rect_128 = LwHash(128, "RECTANGLE", key)
    # print(f"  LwHash-EMLw-128: {bytes_to_hex_string(lwhash_rect_128.compute_hash(message_bytes))}")
    # lwhash_rect_256 = LwHash(256, "RECTANGLE", key)
    # print(f"  LwHash-EMLw-256: {bytes_to_hex_string(lwhash_rect_256.compute_hash(message_bytes))}")
    # lwhash_rect_512 = LwHash(512, "RECTANGLE", key)
    # print(f"  LwHash-EMLw-512: {bytes_to_hex_string(lwhash_rect_512.compute_hash(message_bytes))}")