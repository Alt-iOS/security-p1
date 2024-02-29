import hashlib
import Crypto.Util.number as n
import Crypto as c

# Número de bits
bits = 1024

# Obtener los primos para Bob
pB = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("pB: ", pB, "\n")
qB = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("qB: ", qB, "\n")

# Obtenemos la primera parte de la lave publica de Bob
nB = pB * qB
print("nB: ", nB, "\n")

# Calculamos la funcion phi de n
phiB = (pB - 1) * (qB - 1)
print("phiB: ", phiB, "\n")

# Por razones de eficiencia utilizaremos el número 4 de Fermat, 65537, debido a que es
# un primo largo y no es potencia de 2, y como forma parte de la clave pública
# no  es necesario calcularlo
e = 65537

# Calculamos la clave privada de Bob
dB = n.inverse(e, phiB)
print("dB: ", dB, "\n")

# Mensaje original
M = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam porta cursus ipsum, gravida mattis felis sollicitudin vel.Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Nullam quis volutpat eros, vel tempus lacus. Ut mi ligula, cursus quis metus ac, sollicitudin ullamcorper odio. In placerat quam ipsum, eget volutpat ex tincidunt sit amet. Integer volutpat eu magna non porttitor. Integer augue turpis, fringilla nec lacus in, mattis suscipit massa. Cras commodo et diam ac cursus. Ut ac nibh id sapien fermentum rutrum. Vivamus dignissim consequat nibh, ut laoreet nisi rhoncus quis. Integer congue fringilla ultrices. Sed porttitor leo quis nunc molestie sollicitudin. Suspendisse aliquam lacinia felis, a ullamcorper elit tincidunt eu. Quisque arcu mi, aliquam nec neque sed, consequat consequat augue. Nam efficitur magna lectus, nec varius nulla dignissim ut. Nunc in sem libero. In hac habitasse platea dictumst. Nullam in varius metus. Aliquam varius ligula eget pharetra porta. Ut lorem turpis."
# Longitud del mensaje original
print("Longitud de M:", len(M))

# Hash del mensaje original
h_M = hashlib.sha256(M.encode("utf-8")).hexdigest()
print("Hash de M:", h_M)

# Dividir mensaje en partes de 128 caracteres
parts = [M[i : i + 128] for i in range(0, len(M), 128)]

# Cifrar partes con clave pública de Bob
encrypted_parts = []
for part in parts:
    c = pow(int.from_bytes(part.encode("utf-8"), byteorder="big"), e, nB)
    encrypted_parts.append(c)

# Descifrar partes con clave privada de Bob
decrypted_parts = []
for part in encrypted_parts:
    des = pow(part, dB, nB)
    decrypted_parts.append(des)


len_byte = 8
# Reconstruir mensaje
M_prime = "".join(
    [
        int.to_bytes(
            part, (part.bit_length() + (len_byte - 1)) // len_byte, byteorder="big"
        ).decode("utf-8")
        for part in decrypted_parts
    ]
)

# Hash del mensaje descifrado
h_M_prime = hashlib.sha256(M_prime.encode("utf-8")).hexdigest()
print("Hash de M':", h_M_prime)

# Comparar hashes
if h_M == h_M_prime:
    print("Los mensajes coinciden")
else:
    print("Los mensajes no coinciden")
