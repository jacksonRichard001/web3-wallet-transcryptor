from .encryption import Encryption, EncryptionError, InvalidKeyError, InvalidMessageError

def encrypt(receiver_public_key: str, msg: str) -> dict:
    """
    Encrypt a message using X25519-XSalsa20-Poly1305

    Args:
        receiver_public_key: Base64 encoded public key of the receiver
        msg: Message to encrypt

    Returns:
        dict: Encrypted message data containing version, nonce, ephemeral public key, and ciphertext

    Raises:
        EncryptionError: If encryption fails
        InvalidKeyError: If public key is invalid
        InvalidMessageError: If message is invalid
    """
    encryption = Encryption.create()
    return encryption.encrypt_message(receiver_public_key, msg)
