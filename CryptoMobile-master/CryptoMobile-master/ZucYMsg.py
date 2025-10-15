# Nota: Para ejecutar este código, la librería 'pyzuc' debe estar instalada.

from pyzuc import zuc_initialization, zuc_generatekeystream

# --- 1. Definir los datos de entrada ---
plaintext_message = "ASF impulsa la innovacion digital con IA segura rapida/cnfiable"
key_hex = "000102030405060708090a0b0c0d0e0f"
iv_hex = "101112131415161718191a1b1c1d1e1f"

# --- 2. Preparar los datos para el cifrador ---
# Convertir la clave y el IV de hexadecimal a bytes
key_bytes = bytes.fromhex(key_hex)
iv_bytes = bytes.fromhex(iv_hex)

# Convertir el mensaje de texto a bytes usando UTF-8
plaintext_bytes = plaintext_message.encode('utf-8')
plaintext_len_bytes = len(plaintext_bytes)

# --- 3. Inicializar el cifrador ZUC ---
zuc_initialization(key_bytes, iv_bytes)

# --- 4. Generar el Keystream ---
# Calcular cuántas palabras de 32 bits se necesitan para cubrir el mensaje
# (división por 4 redondeando hacia arriba)
num_words = (plaintext_len_bytes + 3) // 4
full_keystream = zuc_generatekeystream(num_words)

# Asegurarse de que el keystream tenga la misma longitud que el texto plano
keystream = full_keystream[:plaintext_len_bytes]

# --- 5. Realizar el cifrado con la operación XOR ---
ciphertext_bytes = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream)])

# --- 6. Mostrar los resultados ---
print("--- Proceso de Cifrado ZUC ---")
print(f"Mensaje Original: '{plaintext_message}'")
print(f"Clave (hex):       {key_hex}")
print(f"IV (hex):          {iv_hex}\n")
print(f"Longitud del Mensaje: {plaintext_len_bytes} bytes")
print(f"Keystream Generado (hex): {keystream.hex()}\n")

print("--- RESULTADO ---")
print(f"Texto Cifrado (hex):\n{ciphertext_bytes.hex()}")