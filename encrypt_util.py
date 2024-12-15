import nacl.utils
import nacl.public
import base64


def encrypt(receiver_public_key: str, msg: str) -> dict:
    """
    Encrypt a message using X25519-XSalsa20-Poly1305

    Args:
        receiver_public_key (str): Base64 encoded public key of the receiver
        msg (str): Message to encrypt

    Returns:
        dict: Encrypted message data containing version, nonce, ephemeral public key, and ciphertext
    """
    if not isinstance(msg, str):
        raise ValueError("Msg must be a string")

    # Generate ephemeral keypair
    ephemeral_keypair = nacl.public.PrivateKey.generate()

    try:
        # Decode receiver's public key from base64
        pub_key_bytes = base64.b64decode(receiver_public_key)
        receiver_key = nacl.public.PublicKey(pub_key_bytes)
    except Exception:
        raise ValueError("Bad public key")

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

    output = {
        "version": "x25519-xsalsa20-poly1305",
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ephemPublicKey": base64.b64encode(
            ephemeral_keypair.public_key.encode()
        ).decode("utf-8"),
        "ciphertext": base64.b64encode(encrypted_message).decode("utf-8"),
    }

    return output
