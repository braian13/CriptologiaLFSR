from pyzuc import zuc_initialization, zuc_generatekeystream
import numpy as np

# --- Función para calcular la Distancia de Hamming ---
def hamming_distance(bytes1, bytes2):
    """Calcula el número de bits que son diferentes entre dos arrays de bytes."""
    # Usamos XOR: el resultado tendrá un '1' en cada posición donde los bits difieran.
    xor_result = np.frombuffer(bytes1, dtype=np.uint8) ^ np.frombuffer(bytes2, dtype=np.uint8)
    # Contamos el número de bits '1' en el resultado.
    diff_bits = np.unpackbits(xor_result).sum()
    return int(diff_bits)

# --- Datos Originales del Cifrado Anterior ---
plaintext_message = "ASF impulsa la innovacion digital con IA segura rapida/cnfiable"
key_hex = "000102030405060708090a0b0c0d0e0f"
iv_hex = "101112131415161718191a1b1c1d1e1f"

# Convertir a bytes
key_bytes = bytes.fromhex(key_hex)
iv_bytes = bytes.fromhex(iv_hex)
plaintext_bytes = plaintext_message.encode('utf-8')

# --- Cifrado Original ---
zuc_initialization(key_bytes, iv_bytes)
num_words = (len(plaintext_bytes) + 3) // 4
original_ciphertext = zuc_generatekeystream(num_words)[:len(plaintext_bytes)]
original_ciphertext = bytes([p ^ k for p, k in zip(plaintext_bytes, original_ciphertext)])

# --- PRUEBA 1: Avalancha cambiando 1 bit del Texto Plano ---
# Cambiamos el primer bit del primer byte del mensaje (ej. de 01000001 a 01000000)
plaintext_modificado_list = list(plaintext_bytes)
plaintext_modificado_list[0] ^= 0b00000001 
plaintext_modificado_bytes = bytes(plaintext_modificado_list)

# Ciframos el mensaje modificado con la clave original
zuc_initialization(key_bytes, iv_bytes)
keystream_a = zuc_generatekeystream(num_words)[:len(plaintext_bytes)]
ciphertext_a = bytes([p ^ k for p, k in zip(plaintext_modificado_bytes, keystream_a)])

# --- PRUEBA 2: Avalancha cambiando 1 bit de la Clave ---
# Cambiamos el primer bit del primer byte de la clave
key_modificada_list = list(key_bytes)
key_modificada_list[0] ^= 0b00000001
key_modificada_bytes = bytes(key_modificada_list)

# Ciframos el mensaje original con la clave modificada
zuc_initialization(key_modificada_bytes, iv_bytes)
keystream_b = zuc_generatekeystream(num_words)[:len(plaintext_bytes)]
ciphertext_b = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream_b)])

# --- Calcular y Mostrar Resultados ---
total_bits = len(original_ciphertext) * 8

distancia_a = hamming_distance(original_ciphertext, ciphertext_a)
porcentaje_a = (distancia_a / total_bits) * 100

distancia_b = hamming_distance(original_ciphertext, ciphertext_b)
porcentaje_b = (distancia_b / total_bits) * 100

print("--- 🏔️ Resultados de la Prueba de Avalancha ---")
print(f"Longitud del texto cifrado: {len(original_ciphertext)} bytes ({total_bits} bits)")
print("-" * 50)
print("Prueba 1: Cambio de 1 bit en el Texto Plano")
print(f"Bits diferentes (Distancia de Hamming): {distancia_a}")
print(f"Porcentaje de cambio: {porcentaje_a:.2f}%")
print("-" * 50)
print("Prueba 2: Cambio de 1 bit en la Clave")
print(f"Bits diferentes (Distancia de Hamming): {distancia_b}")
print(f"Porcentaje de cambio: {porcentaje_b:.2f}%")
print("\nUn resultado cercano al 50% demuestra un excelente efecto avalancha. ✅")