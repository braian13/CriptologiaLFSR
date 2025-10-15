# Nota: Para ejecutar este código, la librería 'pyzuc' debe estar instalada.

from pyzuc import zuc_initialization, zuc_generatekeystream

def construct_eea3_iv(count: int, bearer: int, direction: int) -> bytes:
    """
    Construye el Vector de Inicialización (IV) de 128 bits (16 bytes) para ZUC-EEA3
    según la especificación 3GPP TS 33.401.
    """
    iv = bytearray(16)
    
    # COUNT (32 bits, big-endian) en los bytes 0-3 y se repite en 8-11.
    iv[0] = (count >> 24) & 0xFF
    iv[1] = (count >> 16) & 0xFF
    iv[2] = (count >> 8) & 0xFF
    iv[3] = count & 0xFF
    iv[8:12] = iv[0:4]

    # BEARER (5 bits) y DIRECTION (1 bit) en los bytes 4 y 12.
    # El formato es: BEARER || DIRECTION || 00
    iv[4] = ((bearer & 0x1F) << 3) | ((direction & 0x01) << 2)
    iv[12] = iv[4]
    
    return bytes(iv)

# --- Datos del Vector de Prueba C.1.1 de 3GPP TS 33.401 ---
key_hex = "d3c5d592327fb11c4035c6680af8c6d1"
count_hex = "398a59b4"
bearer = 15
direction = 1
plaintext_hex = "981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0"
expected_ciphertext_hex = "e9fed8a63d155304d71df20bf3e82214b20ed7dad2f233dc3c22d7bdeeed8e78"

# --- 1. Preparar Entradas ---
key_bytes = bytes.fromhex(key_hex)
count_int = int(count_hex, 16)
plaintext_bytes = bytes.fromhex(plaintext_hex)
expected_ciphertext = bytes.fromhex(expected_ciphertext_hex)

# --- 2. Construir el IV específico para EEA3 ---
iv_bytes = construct_eea3_iv(count_int, bearer, direction)

# --- 3. Inicializar el cifrador ZUC con la clave y el IV construido ---
zuc_initialization(key_bytes, iv_bytes)

# --- 4. Generar el Keystream ---
# Necesitamos 32 bytes de keystream, que son 8 palabras de 32 bits (8 * 4 = 32).
keystream = zuc_generatekeystream(8)

# --- 5. Operación XOR para obtener el Texto Cifrado ---
calculated_ciphertext = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream)])

# --- 6. Imprimir y Verificar Resultados ---
expected_keystream_hex = "71e57e24710ea81e6398b52bda5f3f943eede9f611328620231f3f1b328b3f88"

print("Parámetros de Entrada:")
print(f"  - Key (hex):              {key_hex}")
print(f"  - Count (hex):            {count_hex}")
print(f"  - Bearer:                 {bearer}")
print(f"  - Direction:              {direction}")
print(f"  - IV Construido (hex):    {iv_bytes.hex()}\n")

print("Resultados de la Criptografía:")
print(f"  - Plaintext:                {plaintext_hex}")
print(f"  - Keystream Generado:       {keystream.hex()}")
print(f"  - Keystream Esperado:       {expected_keystream_hex}")
print("-" * 95)
print(f"  - Ciphertext Calculado:     {calculated_ciphertext.hex()}")
print(f"  - Ciphertext Esperado:      {expected_ciphertext_hex}\n")

# --- Verificación Final ---
if calculated_ciphertext == expected_ciphertext:
    print("Validación exitosa")
else:
    print("Validación fallida")