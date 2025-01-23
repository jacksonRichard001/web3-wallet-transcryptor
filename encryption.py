import nacl.utils
import nacl.public
import base64
from typing import Dict, Union, Optional
from dataclasses import dataclass


@dataclass
class EncryptedMessage:
    version: str
    nonce: str
    ephemPublicKey: str
    ciphertext: str


class EncryptionError(Exception):
    """Base exception for encryption errors"""

    pass


class InvalidKeyError(EncryptionError):
    """Exception raised for invalid key errors"""

    pass


class InvalidMessageError(EncryptionError):
    """Exception raised for invalid message errors"""

    pass


class Encryption:
    VERSION = "x25519-xsalsa20-poly1305"
    MAX_MESSAGE_LENGTH = 1024 * 1024  # 1MB limit

    @staticmethod
    def _validate_message(msg: str) -> None:
        """
        Validate the message to be encrypted

        Args:
            msg: Message to validate

        Raises:
            InvalidMessageError: If message is invalid
        """
        if not isinstance(msg, str):
            raise InvalidMessageError("Message must be a string")

        if len(msg.encode("utf-8")) > Encryption.MAX_MESSAGE_LENGTH:
            raise InvalidMessageError(
                f"Message exceeds maximum length of {Encryption.MAX_MESSAGE_LENGTH} bytes"
            )

        if not msg:
            raise InvalidMessageError("Message cannot be empty")

    @staticmethod
    def _validate_public_key(key: str) -> None:
        """
        Validate the public key format

        Args:
            key: Public key to validate

        Raises:
            InvalidKeyError: If key is invalid
        """
        if not isinstance(key, str):
            raise InvalidKeyError("Public key must be a string")

        if not key:
            raise InvalidKeyError("Public key cannot be empty")

        try:
            decoded_key = base64.b64decode(key)
            if len(decoded_key) != nacl.public.PublicKey.SIZE:
                raise InvalidKeyError(f"Invalid public key length: {len(decoded_key)}")
        except Exception as e:
            raise InvalidKeyError(f"Invalid public key format: {str(e)}")

    @staticmethod
    def _encode_base64(data: bytes) -> str:
        """Safely encode bytes to base64 string"""
        try:
            return base64.b64encode(data).decode("utf-8")
        except Exception as e:
            raise EncryptionError(f"Failed to encode data: {str(e)}")

    def encrypt_message(self, receiver_public_key: str, msg: str) -> Dict[str, str]:
        """
        Encrypt a message using X25519-XSalsa20-Poly1305

        Args:
            receiver_public_key: Base64 encoded public key of the receiver
            msg: Message to encrypt

        Returns:
            Dict containing encrypted message data

        Raises:
            EncryptionError: If encryption fails
            InvalidKeyError: If public key is invalid
            InvalidMessageError: If message is invalid
        """
        try:
            # Validate inputs
            self._validate_message(msg)
            self._validate_public_key(receiver_public_key)

            # Generate ephemeral keypair
            ephemeral_keypair = nacl.public.PrivateKey.generate()

            # Decode receiver's public key
            pub_key_bytes = base64.b64decode(receiver_public_key)
            receiver_key = nacl.public.PublicKey(pub_key_bytes)

            # Convert message to bytes
            msg_bytes = msg.encode("utf-8")

            # Generate random nonce
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)

            # Create encryption box
            box = nacl.public.Box(ephemeral_keypair, receiver_key)

            # Encrypt the message
            encrypted_message = box.encrypt(msg_bytes, nonce)[
                24:
            ]  # Remove nonce from returned bytes

            # Create encrypted message object
            encrypted_data = EncryptedMessage(
                version=self.VERSION,
                nonce=self._encode_base64(nonce),
                ephemPublicKey=self._encode_base64(
                    ephemeral_keypair.public_key.encode()
                ),
                ciphertext=self._encode_base64(encrypted_message),
            )

            return vars(encrypted_data)

        except (InvalidKeyError, InvalidMessageError):
            raise
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")

    @classmethod
    def create(cls) -> "Encryption":
        """Factory method for creating Encryption instances"""
        return cls()
