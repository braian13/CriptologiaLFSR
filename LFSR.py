from typing import List

# ------------------ LFSR ------------------
class LFSR:
    def __init__(self, bits: List[int], taps: List[int]):
        self.bits = bits[:]  # MSB first
        self.n = len(bits)
        self.taps = taps[:]
    
    def cycle(self) -> int:
        fb = 0
        for t in self.taps:
            fb ^= self.bits[t]
        out = self.bits[-1]  # LSB de salida
        for i in range(self.n-1, 0, -1):
            self.bits[i] = self.bits[i-1]
        self.bits[0] = fb
        return out

# 3) Envía los 40 bits a los registros fijando un 1 en el bit más significativo de 
# cada registro, los 16 bits más significativos se enviarán al registro s1 
# (17 bits) y los 24 bits
def seed_to_registers(seed40: str):
    if len(seed40) != 40 or any(c not in '01' for c in seed40):
        raise ValueError("La semilla debe ser una cadena de 40 caracteres '0'/'1'.")
    s1_bits = [1] + [int(b) for b in seed40[0:16]]
    s2_bits = [1] + [int(b) for b in seed40[16:40]]
    return s1_bits, s2_bits

# ------------------ Generación de keystream ------------------
def generate_keystream(seed40: str, nbytes: int):
    s1_bits, s2_bits = seed_to_registers(seed40)
    
    # tap_index=(n−1)−j donde n es el grado del polinomio y j es el exponente del término
    taps_s1 = [9,10,12,14,15,16] # Correspondiente a los términos , x^7, x^6, x^4, x^2, x^1, x^0
    taps_s2 = [5,12,13,17,19,23] # Correspondiente a los términos , x^19, x^12, x^11, x^5, x^1, x^0
    
    lfsr1 = LFSR(s1_bits, taps_s1)
    lfsr2 = LFSR(s2_bits, taps_s2)
    
    keystream = []
    c = 0 # acarreo inicial 0
    for _ in range(nbytes):
        xi = 0
        #2) Establece el bloque de salida de 8 bits
        for _ in range(8):
            xi = (xi << 1) | lfsr1.cycle()
        #print(f"LFSR1 State: {''.join(map(str, lfsr1.bits))} | Bit out: {xi & 1} | xi: {xi:08b} ({xi}) ")
        yi = 0
        #2) Establece el bloque de salida de 8 bits
        for _ in range(8):
            yi = (yi << 1) | lfsr2.cycle()
        #print(f"LFSR2 State: {''.join(map(str, lfsr2.bits))} | Bit out: {yi & 1} | xi: {yi:08b} ({yi}) ")

        sum_xy = xi + yi
        z = (sum_xy + c) % 256
        c = 1 if sum_xy > 255 else 0
        keystream.append(z)
    return keystream

# ------------------ Cifrado / Descifrado ------------------
def encrypt_bytes(plaintext_bytes: bytes, seed40: str) -> bytes:
    ks = generate_keystream(seed40, len(plaintext_bytes))
    ciphertext = bytes([pb ^ k for pb, k in zip(plaintext_bytes, ks)])
    return ciphertext

def decrypt_bytes(ciphertext_bytes: bytes, seed40: str, taps_s1=None, taps_s2=None) -> bytes:
    return encrypt_bytes(ciphertext_bytes, seed40)

# ------------------ Utilidades de impresión ------------------
def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def bytes_to_bin(b: bytes) -> str:
    return ' '.join(format(x, '08b') for x in b)


def avalanche_test(seed: str, nbytes: int = 8):
    print("===== PRUEBA DE AVALANCHA =====")
    print(f"Semilla original: {seed}")

    # Keystream con semilla original
    ks1 = generate_keystream(seed, nbytes)

    for i in range(len(seed)):
        # Flipping del bit i
        flipped_seed = list(seed)
        flipped_seed[i] = '1' if seed[i] == '0' else '0'
        flipped_seed = "".join(flipped_seed)

        ks2 = generate_keystream(flipped_seed, nbytes)

        # Comparación bit a bit
        diff_bits = 0
        total_bits = nbytes * 8
        for b1, b2 in zip(ks1, ks2):
            diff_bits += bin(b1 ^ b2).count("1")

        print(f"\nBit cambiado en posición {i+1}:")
        print(f"Semilla original: {seed}")
        print(f"Semilla nueva:    {flipped_seed}")
        print(f"Keystream original: {[f'{b:08b}' for b in ks1]}")
        print(f"Keystream nuevo:    {[f'{b:08b}' for b in ks2]}")
        print(f"Diferencia de bits en keystream: {diff_bits}/{total_bits} "
              f"({100*diff_bits/total_bits:.2f}%)")


# ------------------ Ejemplo ------------------
if __name__ == "__main__":
    # 1) Recibe la semilla (clave) de 40 bits {0,1}^40
    seed = "0011101010110101111010110010101011101011"  
    msg = "ASF impulsa la innovacion digital con IA segura  rapida/cnfiable".encode('utf-8')
    
    # Cifrado
    ct = encrypt_bytes(msg, seed)
    # Descifrado
    pt = decrypt_bytes(ct, seed)
    # Keystream
    ks = generate_keystream(seed, len(msg))
    ks_bytes = bytes(ks)

    print("========== MENSAJE ORIGINAL ==========")
    print("Texto:   ", msg.decode('utf-8'))
    print("Hex:     ", bytes_to_hex(msg))
    print("Binario: ", bytes_to_bin(msg))

    print("\n========== KEYSTREAM ==========")
    print("Hex:     ", bytes_to_hex(ks_bytes))
    print("Binario: ", bytes_to_bin(ks_bytes))

    print("\n========== CIPHERTEXT ==========")
    print("Bytes:   ", ct)
    print("Hex:     ", bytes_to_hex(ct))
    print("Binario: ", bytes_to_bin(ct))

    print("\n========== DESCIFRADO ==========")
    print("Hex:     ", bytes_to_hex(pt))
    print("Binario: ", bytes_to_bin(pt))
    print("Texto:   ", pt.decode('utf-8'))


    avalanche_test(seed, nbytes=8)