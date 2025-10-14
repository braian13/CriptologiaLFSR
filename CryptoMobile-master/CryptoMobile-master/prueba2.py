# zuc_validator.py

from Crypto.Cipher import ZUC

def construct_eea3_iv(count: int, bearer: int, direction: int) -> bytes:
    """
    Construye el Vector de Inicialización (IV) de 128 bits (16 bytes) para ZUC-EEA3
    según la especificación 3GPP TS 33.401.
    """
    iv = bytearray(16)
    iv[0] = (count >> 24) & 0xFF
    iv[1] = (count >> 16) & 0xFF
    iv[2] = (count >> 8) & 0xFF
    iv[3] = count & 0xFF
    iv[8:12] = iv[0:4]
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

# --- 2. Construir el IV ---
iv_bytes = construct_eea3_iv(count_int, bearer, direction)

# --- 3. Inicializar Cifrador y Generar Keystream ---
cipher = ZUC.new(key=key_bytes, iv=iv_bytes)
null_plaintext = b'\x00' * len(plaintext_bytes)
keystream = cipher.encrypt(null_plaintext)

# --- 4. Operación XOR para obtener el Texto Cifrado ---
calculated_ciphertext = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream)])

# --- 5. Imprimir y Verificar Resultados ---
expected_keystream_hex = "71e57e24710ea81e6398b52bda5f3f943eede9f611328620231f3f1b328b3f88"

print("--- Validación con PyCryptodome (Librería Estándar) ---")
print(f"  - Key (hex):              {key_hex}")
print(f"  - Count (hex):            {count_hex}")
print(f"  - IV Construido (hex):    {iv_bytes.hex()}\n")
print(f"  - Keystream Generado:       {keystream.hex()}")
print(f"  - Keystream Esperado:       {expected_keystream_hex}")
print("-" * 95)
print(f"  - Ciphertext Calculado:     {calculated_ciphertext.hex()}")
print(f"  - Ciphertext Esperado:      {expected_ciphertext_hex}\n")

# --- Verificación Final ---
if calculated_ciphertext == expected_ciphertext:
    print("✅ Validación exitosa: El texto cifrado calculado coincide con el valor esperado.")
else:
    print("❌ Validación fallida: El texto cifrado no coincide con el esperado.")