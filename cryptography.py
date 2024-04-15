# Aquí se implementarán las funciones de criptografía
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os
import hashlib
from cryptography.exceptions import InvalidSignature
from io import BytesIO

class CryptoUtils:
    @staticmethod
    def generate_asymmetric_keys():
        """
        Genera un par de claves asimétricas (clave pública y privada).

        Returns:
            tuple: La clave privada y la clave pública.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem, public_key

  """  @staticmethod
    def encrypt_key(key, password):
        
        Cifra una clave privada con una contraseña.

        Args:
            key (bytes): La clave privada a cifrar.
            password (str): La contraseña para cifrar la clave.

        Returns:
            bytes: La clave privada cifrada.
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        encrypted_key = f.encrypt(key)
        return encrypted_key"""
    
    ##ESTA FUNCION ES IGUAL QUE ENCRYPT_PRIVATE_KEY CHECAR ESOOOOOO

    @staticmethod
    def derive_symmetric_key(password):
        """
        Deriva una clave de cifrado simétrica de la contraseña del usuario.

        Args:
            password (str): La contraseña del usuario.

        Returns:
            bytes: La clave de cifrado simétrica.
        """
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def encrypt_message(message, key):
        """
        Cifra un mensaje con una clave simétrica.

        Args:
            message (str): El mensaje a cifrar.
            key (bytes): La clave simétrica.

        Returns:
            bytes: El mensaje cifrado.
        """
        f = Fernet(key)
        return f.encrypt(message.encode())

#propuesta desencriptado del mensaje 
    @staticmethod
    def decrypt_message(encrypted_message, key):
        # Initialize a Fernet cipher with the symmetric key
        f = Fernet(key)
    
        # Decrypt the encrypted message
        decrypted_message = f.decrypt(encrypted_message).decode()
    
        return decrypted_message 

    @staticmethod
    def encrypt_symmetric_key(symmetric_key, public_key):
        """
        Cifra una clave simétrica con una clave pública.

        Args:
            symmetric_key (bytes): La clave simétrica a cifrar.
            public_key (str): La clave pública para cifrar la clave simétrica.

        Returns:
            bytes: La clave simétrica cifrada.
        """
        public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )
        return public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
# propuesta para la decryption de la llave simetrica
    @staticmethod
    def decrypt_symmetric_key(encrypted_symmetric_key, private_key):
    # Load the private key
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
    
    # Decrypt the encrypted symmetric key
        decrypted_symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    return decrypted_symmetric_key

    @staticmethod
    def generate_hash(message, algorithm='sha256'):
        """
        Genera un resumen de mensaje para la verificación de integridad.

        Args:
            message (str): El mensaje para el cual se generará el resumen.
            algorithm (str): El algoritmo de hash a utilizar ('sha256' para SHA-2, 'sha3_256' para SHA-3).

        Returns:
            str: El resumen de mensaje en formato byte string.
        """
        h = hashlib.new(algorithm)
        h.update(message.encode())
        return h.digest() ## cambio de h.hexdigest() a h.digest()

    @staticmethod
    def create_digital_signature(message, private_key):
        """
        Crea una firma digital con una clave privada y la adjunta al mensaje.

        Args:
            message (str): El mensaje al que se adjuntará la firma.
            private_key (str): La clave privada para crear la firma.

        Returns:
            bytes: La firma digital.
        """
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
        return private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify_signature(message, signature, public_key):
        """
        Verifica una firma digital con una clave pública.

        Args:
            message (str): El mensaje original.
            signature (bytes): La firma digital.
            public_key (str): La clave pública del remitente.

        Returns:
            bool: True si la firma es válida, False en caso contrario.
        """
        public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def encrypt_private_key(private_key, password):
        """
        Cifra una clave privada con una contraseña.

        Args:
            private_key (bytes): La clave privada a cifrar.
            password (str): La contraseña para cifrar la clave.

        Returns:
            bytes: La clave privada cifrada.
        """
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        return f.encrypt(private_key)



    # creacion de un método propuesto para decrypt las llaves usando AES
    @staticmethod
    def decrypt_private_key(encrypted_private_key, password):
        # Derive the Fernet key from the password using PBKDF2
        salt = encrypted_private_key[:16]  # Extract the salt from the ciphertext
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
        # Initialize a Fernet cipher with the derived key
        f = Fernet(key)
    
        # Decrypt the encrypted private key
        decrypted_private_key = f.decrypt(encrypted_private_key[16:])  # Exclude the salt
    
        return decrypted_private_key


    @staticmethod
    def encrypt_keys_for_storage(username, password, priv_asym_key, pub_asym_key, sym_key):
        
        encrypted_file = BytesIO()                                                  ## creacion de un objeto bytesio
        derived_key_string = username + password
        derived_key_hash = generate_hash(derived_key_string, 'sha256')              ## obtencion del hash usando username y password
        sym_key = encrypt_private_key(sym_key,derived_key_hash)                     ## encripcion usando AES de las llaves
        priv_asym_key = encrypt_private_key(PrivateFormat,derived_key_hash)
        pub_asym_key = encrypt_private_key(pub_asym_key,derived_key_hash)
        encrypted_file.write(priv_asym_key)                                               ## escritura de las llaves cifradas en el objeto BytesIO
        encrypted_file.write(pub_asym_key)
        encrypted_file.write(sym_key)
        encrypted_file.seek(0)                                                      ## reseteo del puntero a la posición inicial 
        return encrypted_file


    

