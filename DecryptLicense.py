from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes

# Settings from Django where the ENCRYPTED_SYMMETRIC_KEY
# and PRIVATE_KEY are loaded, then used in the script
from django.conf import settings

import json


def data_decryptor(encrypted_data: str) -> json:
    """
    Description:
        Расшифровывает лицензию активации VMList.
        Расшифровка происходит используя симметричный ключ.
        Сам симметричный ключ зашифрован нашим публичным ключом

    Parametrs:
        ::encrypted_data - зашифрованный нами ключ

    Example:
        data_decryptor(
            encrypted_data=key
        )

    Returns:
        Возвращается расшифрованный JSON или ошибка о том, что лицензия не валидна
    """
    try:
        # Decrypt the encrypted data using the symmetric key
        fernet = Fernet(__decrypt_symmetric_key())
        decrypted_data = fernet.decrypt(encrypted_data)

    except InvalidToken:
        raise InvalidToken("Invalid license key, please contact Tecom for future instructions")

    else:
        # Decode the decrypted data and load it as JSON
        json_data = json.loads(decrypted_data.decode())
        
        return json_data

def __decrypt_symmetric_key() -> bytes:
    """
    Description:
        Расшифровыват симметричный ключ используя наш приватный ключ

    Returns:
        Возвращается расшифрованный симметричный ключ
    """
    # Decrypt the symmetric key using the private key
    symmetric_key = settings.PRIVATE_KEY.decrypt(
        settings.ENCRYPTED_SYMMETRIC_KEY,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return symmetric_key
