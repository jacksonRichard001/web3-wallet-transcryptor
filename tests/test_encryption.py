import pytest
import base64
import json
from encrypt_util import encrypt

def test_encrypt_message_success():
    """Test successful encryption of a message"""
    # Arrange
    # Generate a valid public key for testing (using nacl to create one)
    import nacl.public
    test_private_key = nacl.public.PrivateKey.generate()
    test_public_key = test_private_key.public_key
    
    # Convert the public key to base64 string as expected by the encrypt function
    receiver_public_key = base64.b64encode(bytes(test_public_key)).decode('utf-8')
    test_message = "Hello, World!"

    # Act
    encrypted_data = encrypt(receiver_public_key, test_message)

    # Assert
    assert isinstance(encrypted_data, dict)
    assert encrypted_data['version'] == 'x25519-xsalsa20-poly1305'
    assert all(key in encrypted_data for key in [
        'version',
        'nonce',
        'ephemPublicKey',
        'ciphertext'
    ])
    
    # Verify all values are base64 encoded strings
    assert all(isinstance(encrypted_data[key], str) 
              for key in ['nonce', 'ephemPublicKey', 'ciphertext'])
    
    # Verify we can decode the base64 strings
    try:
        base64.b64decode(encrypted_data['nonce'])
        base64.b64decode(encrypted_data['ephemPublicKey'])
        base64.b64decode(encrypted_data['ciphertext'])
    except Exception as e:
        pytest.fail(f"Failed to decode base64 strings: {e}") 