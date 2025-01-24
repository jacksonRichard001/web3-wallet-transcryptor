import pytest
import base64
import nacl.public
from encryption import Encryption, EncryptionError, InvalidKeyError, InvalidMessageError


@pytest.fixture
def encryption():
    return Encryption.create()


@pytest.fixture
def valid_keypair():
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    return {
        "private_key": private_key,
        "public_key": public_key,
        "public_key_b64": base64.b64encode(bytes(public_key)).decode("utf-8"),
    }


def test_encryption_create():
    """Test the factory method creates an instance"""
    encryption = Encryption.create()
    encryption = encryption  # To avoid linting error()
    assert isinstance(encryption, Encryption)


class TestMessageValidation:
    def test_validate_valid_message(self, encryption):
        """Test that a valid message passes validation"""
        encryption._validate_message("Hello, World!")

    def test_validate_empty_message(self, encryption):
        """Test that empty message raises InvalidMessageError"""
        with pytest.raises(InvalidMessageError, match="Message cannot be empty"):
            encryption._validate_message("")

    def test_validate_non_string_message(self, encryption):
        """Test that non-string message raises InvalidMessageError"""
        with pytest.raises(InvalidMessageError, match="Message must be a string"):
            encryption._validate_message(123)

    def test_validate_too_long_message(self, encryption):
        """Test that message exceeding max length raises InvalidMessageError"""
        long_message = "x" * (Encryption.MAX_MESSAGE_LENGTH + 1)
        with pytest.raises(InvalidMessageError, match="Message exceeds maximum length"):
            encryption._validate_message(long_message)


class TestPublicKeyValidation:
    def test_validate_valid_public_key(self, encryption, valid_keypair):
        """Test that a valid public key passes validation"""
        encryption._validate_public_key(valid_keypair["public_key_b64"])

    def test_validate_empty_public_key(self, encryption):
        """Test that empty public key raises InvalidKeyError"""
        with pytest.raises(InvalidKeyError, match="Public key cannot be empty"):
            encryption._validate_public_key("")

    def test_validate_non_string_public_key(self, encryption):
        """Test that non-string public key raises InvalidKeyError"""
        with pytest.raises(InvalidKeyError, match="Public key must be a string"):
            encryption._validate_public_key(123)

    def test_validate_invalid_base64_public_key(self, encryption):
        """Test that invalid base64 public key raises InvalidKeyError"""
        with pytest.raises(InvalidKeyError, match="Invalid public key format"):
            encryption._validate_public_key("not-base64!")

    def test_validate_wrong_length_public_key(self, encryption):
        """Test that wrong length public key raises InvalidKeyError"""
        invalid_key = base64.b64encode(b"too short").decode("utf-8")
        with pytest.raises(InvalidKeyError, match="Invalid public key length"):
            encryption._validate_public_key(invalid_key)


class TestEncryptMessage:
    def test_successful_encryption(self, encryption, valid_keypair):
        """Test successful message encryption"""
        message = "Hello, World!"
        result = encryption.encrypt_message(valid_keypair["public_key_b64"], message)

        # Check the structure and content of the encrypted result
        assert isinstance(result, dict)
        assert result["version"] == Encryption.VERSION
        assert all(
            key in result
            for key in ["version", "nonce", "ephemPublicKey", "ciphertext"]
        )

        # Verify all values are non-empty strings
        assert all(isinstance(value, str) and value for value in result.values())

        # Verify base64 encoding of components
        assert base64.b64decode(result["nonce"])
        assert base64.b64decode(result["ephemPublicKey"])
        assert base64.b64decode(result["ciphertext"])

    def test_encryption_with_invalid_public_key(self, encryption):
        """Test encryption with invalid public key raises error"""
        with pytest.raises(InvalidKeyError):
            encryption.encrypt_message("invalid-key", "Hello, World!")

    def test_encryption_with_invalid_message(self, encryption, valid_keypair):
        """Test encryption with invalid message raises error"""
        with pytest.raises(InvalidMessageError):
            encryption.encrypt_message(valid_keypair["public_key_b64"], "")


def test_encode_base64_success(encryption):
    """Test successful base64 encoding"""
    test_bytes = b"Hello, World!"
    encoded = encryption._encode_base64(test_bytes)
    assert isinstance(encoded, str)
    assert base64.b64decode(encoded) == test_bytes


def test_encode_base64_failure(encryption):
    """Test base64 encoding with invalid input"""
    with pytest.raises(EncryptionError, match="Failed to encode data"):
        # Creating an invalid input that will fail encoding
        class BadBytes:
            def __bytes__(self):
                raise Exception("Conversion failed")

        encryption._encode_base64(BadBytes())
