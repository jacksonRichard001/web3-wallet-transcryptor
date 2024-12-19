import pytest
import base64
import json
from encrypt_util import encrypt
from encryption import Encryption
from transcryptor import Transcryptor
import nacl.public


class TestEncryption:
    @pytest.fixture
    def valid_key_pair(self):
        """Fixture to generate valid key pairs for testing"""
        test_private_key = nacl.public.PrivateKey.generate()
        test_public_key = test_private_key.public_key
        receiver_public_key = base64.b64encode(bytes(test_public_key)).decode('utf-8')
        return receiver_public_key, test_private_key

    def test_encrypt_message_success(self, valid_key_pair):
        """Test successful encryption of a message"""
        receiver_public_key, _ = valid_key_pair
        test_message = "Hello, World!"

        encrypted_data = encrypt(receiver_public_key, test_message)

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

    def test_encrypt_invalid_message_type(self, valid_key_pair):
        """Test encryption with invalid message type"""
        receiver_public_key, _ = valid_key_pair
        invalid_messages = [
            123,  # integer
            ["test"],  # list
            {"message": "test"},  # dict
            None  # None
        ]

        for invalid_msg in invalid_messages:
            with pytest.raises(ValueError, match="Msg must be a string"):
                encrypt(receiver_public_key, invalid_msg)

    def test_encrypt_invalid_public_key(self):
        """Test encryption with invalid public key"""
        invalid_keys = [
            "invalid-base64",  # invalid base64
            "YWJjZGVm",  # valid base64 but invalid key
            "",  # empty string
            None  # None
        ]

        for invalid_key in invalid_keys:
            with pytest.raises(ValueError, match="Bad public key"):
                encrypt(invalid_key, "test message")

    def test_encryption_class_integration(self, valid_key_pair):
        """Test the Encryption class implementation"""
        receiver_public_key, _ = valid_key_pair
        test_message = "Test message for encryption class"
        
        encryption = Encryption()
        encrypted_data = encryption.encrypt_message(receiver_public_key, test_message)
        
        assert isinstance(encrypted_data, dict)
        assert encrypted_data['version'] == 'x25519-xsalsa20-poly1305'
        assert all(key in encrypted_data for key in [
            'version',
            'nonce',
            'ephemPublicKey',
            'ciphertext'
        ])

    @pytest.mark.asyncio
    async def test_transcryptor_initialization(self):
        """Test Transcryptor initialization"""
        transcryptor = Transcryptor()
        
        with pytest.raises(Exception, match="Failed to connect to Web3 provider"):
            await transcryptor._init()

    @pytest.mark.asyncio
    async def test_transcryptor_encrypt_without_web3(self):
        """Test Transcryptor encryption without Web3 initialization"""
        transcryptor = Transcryptor()
        test_data = {"message": "test"}
        
        with pytest.raises(Exception):
            await transcryptor.encrypt_public_key(test_data)

    def test_empty_message_encryption(self, valid_key_pair):
        """Test encryption of empty string"""
        receiver_public_key, _ = valid_key_pair
        empty_message = ""
        
        encrypted_data = encrypt(receiver_public_key, empty_message)
        assert isinstance(encrypted_data, dict)
        assert all(key in encrypted_data for key in [
            'version',
            'nonce',
            'ephemPublicKey',
            'ciphertext'
        ])

    def test_long_message_encryption(self, valid_key_pair):
        """Test encryption of a long message"""
        receiver_public_key, _ = valid_key_pair
        long_message = "x" * 1000  # 1000 character message
        
        encrypted_data = encrypt(receiver_public_key, long_message)
        assert isinstance(encrypted_data, dict)
        assert all(key in encrypted_data for key in [
            'version',
            'nonce',
            'ephemPublicKey',
            'ciphertext'
        ])