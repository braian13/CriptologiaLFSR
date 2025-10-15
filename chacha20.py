def rotl32(v, n):
    """Rotación a la izquierda de 32 bits."""
    return ((v << n) & 0xffffffff) | (v >> (32 - n))


def qr(a, b, c, d):
    """Quarter Round de ChaCha20 (RFC 7539 Sección 2.1.1)."""
    a = (a + b) & 0xffffffff
    d ^= a
    d = rotl32(d, 16)

    c = (c + d) & 0xffffffff
    b ^= c
    b = rotl32(b, 12)

    a = (a + b) & 0xffffffff
    d ^= a
    d = rotl32(d, 8)

    c = (c + d) & 0xffffffff
    b ^= c
    b = rotl32(b, 7)

    return a, b, c, d


def chacha_block(input_words):
    """Función de bloque ChaCha20 (20 rondas = 10 iteraciones de 2 rondas)."""
    if len(input_words) != 16:
        raise ValueError("El bloque de entrada debe tener exactamente 16 palabras de 32 bits.")
   
    x = list(input_words)
    ROUNDS = 20

    for i in range(0, ROUNDS, 2):
        # Ronda impar: columnas
        x[0], x[4], x[8], x[12] = qr(x[0], x[4], x[8], x[12])
        x[1], x[5], x[9], x[13] = qr(x[1], x[5], x[9], x[13])
        x[2], x[6], x[10], x[14] = qr(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = qr(x[3], x[7], x[11], x[15])

        # Ronda par: diagonales
        x[0], x[5], x[10], x[15] = qr(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = qr(x[1], x[6], x[11], x[12])
        x[2], x[7], x[8], x[13] = qr(x[2], x[7], x[8], x[13])
        x[3], x[4], x[9], x[14] = qr(x[3], x[4], x[9], x[14])
   
    # Suma con el estado original
    output = [(x[i] + input_words[i]) & 0xffffffff for i in range(16)]
    return output


# ---------------------------------------------------------------
# Prueba oficial del RFC 7539 Sección 2.3.2
# ---------------------------------------------------------------
if _name_ == "_main_":
    test_input = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000
    ]

    expected_output = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    ]

    output = chacha_block(test_input)

    print("🔹 Resultado del algoritmo ChaCha20 (20 rondas):\n")
    for i, w in enumerate(output):
        print(f"x[{i:2d}] = 0x{w:08x}")

    # Comparar con el resultado esperado
    if output == expected_output:
        print("\n✅ La implementación es correcta (coincide con el RFC 7539 sección 2.3.2).")
    else:
        print("\n❌ La implementación NO coincide con el resultado esperado.")