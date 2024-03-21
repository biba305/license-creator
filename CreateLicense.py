from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

import json
import os


class EncryptLicense():
    """
    Description:
        Класс для создания зашифрованной лицензии используя приватный, публичный и симметричный ключ. 
        В классе нет параметров для передачи при инициализации, нужно только создать экземпляр класса 
        и использовать метод encrypt_data
    
    Принцип работы:
        1. Скрипт шифрует сообщение с помощью симметричного ключа, однако сам симметричный ключ
        зашифрован с помощью нашего публичного ключа (т.е. использовать симметричный ключ может только тот
        у кого есть наш приватный ключ)
        2. Если скрипт выявит, что симметричного ключа нет, то он создаст его
        3. Если скрипт выявит, что приватного и публичного ключа нет, то также их создаст
        4. Файл license.key является конечным файлом лицензии и его нужно отправлять клиенту

    Parameters:
        Нет параметров для передачи при инициализации
    """

    def __init__(self):
        self.private_key_name = "private_key.pem"
        self.public_key_name = "public_key.pem"
        self.symmetric_key_name = "symmetric_key.bin"
        self.encrypted_symmetric_key_name = "encrypted_symmetric_key.bin"
        self.license_key_name = "license.key"

    def encrypt_data(self, license: bytes):
        """
        Description:
            Шифрует предоставленные данные лицензии с помощью симметричного ключа. 
            В качестве входных данных принимается объект JSON, представляющий данные лицензии. 
            Зашифрованные данные лицензии сохраняются в файле с именем "license.key"

        Parametrs:
            ::license - bytes данные, которые мы хотим зашифровать

        Example:
            encrypt.encrypt_data(
                license=data
            )

        Returns:
            Эта функция не вернёт ничего, но создаст файл "license.key", в котором хранится ключ активации VMList
        """
        # encrypting the data
        fernet = Fernet(self.__symmetric_key())
        encrypted_data = fernet.encrypt(license)

        # save the encrypted licnese to .key file
        self.__save_file(
            filename=self.license_key_name,
            content=encrypted_data,
            mode="wb"
        )

    def __private_key(self):
        """
        Description:
            Загружает приватный ключ, если он существует, или генерирует новый приватный ключ, если он не существует. 
            Возвращается приватный ключ
        """
        # load private key if exists
        if os.path.exists(self.private_key_name):
            private_key = self.__read_file(
                filename=self.private_key_name,
                mode="rb"
            )

        else:
            # Generate private key if do not exists
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )

            # Save the private key in PEM format
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            self.__save_file(
                filename=self.private_key_name,
                content=pem,
                mode="wb"
            )

        return private_key

    def __public_key(self):
        """
        Description:
            Загружает публичный ключ, если он существует, или генерирует новый публичный ключ, используя приватный ключ. 
            Возвращается публичный ключ
        """
        # load public key if exists
        if os.path.exists(self.public_key_name):
            public_pem = self.__read_file(
                filename=self.public_key_name,
                mode="rb"
            )

        else:
            # Generate public key if do not exists
            public_key = self.__private_key().public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Save the public key
            self.__save_file(
                filename=self.public_key_name,
                content=public_pem,
                mode="wb"
            )

        return public_pem

    def __symmetric_key(self) -> bytes:
        """
        Description:
            Загружает симметричный ключ, если он существует, или генерирует новый симметричный ключ. 
            Если симметричный ключ не существует, генерирует новый симметричный ключ, 
            шифрует его с помощью открытого ключа и сохраняет исходный и зашифрованный симметричные ключи в отдельных файлах. 
            Симметричный ключ возвращается
        """
        # load symmetric key if exists
        if os.path.exists(self.symmetric_key_name):
            symmetric_key = self.__read_file(
                filename=self.symmetric_key_name,
                mode="rb"
            )
            
        else:
            # Generate symmetric key if do not exists
            symmetric_key = Fernet.generate_key()

            recipient_public_key = serialization.load_pem_public_key(
                self.__public_key(),
                backend=default_backend()
            )

            # Encrypt symmetric key with the public key
            encrypted_symmetric_key = recipient_public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Save original symmetric key
            self.__save_file(
                filename=self.symmetric_key_name, 
                content=symmetric_key,
                mode="wb"
            )

            # Save encrypted symmetric key
            self.__save_file(
                filename=self.encrypted_symmetric_key_name, 
                content=encrypted_symmetric_key,
                mode="wb"
            )

        return symmetric_key

    def __save_file(self, filename: str, content, mode: str):
        """
        Description:
            сохраняет файл
        """
        with open(filename, mode) as file:
            return file.write(content)

    def __read_file(self, filename: str, mode: str):
        """
        Description:
            читает файл
        """
        with open(filename) as file:
            return file.read()


if __name__ == "__main__":
    data = {
        'uid': input("Введите UID сервера клиента: "),
        'hypervisors_amount': input("Введите количество поддерживаемых гипервизоров: "),
        'hypervisors_type': list(str(hypervisor) for hypervisor in input("Введите все поддерживаемые типы гипервизоров (через пробел): ").split(" "))
    }

    new = EncryptLicense()
    new.encrypt_data(license=json.dumps(data).encode())