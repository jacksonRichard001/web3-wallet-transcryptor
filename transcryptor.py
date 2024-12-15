from web3 import Web3
from eth_typing import HexStr
from typing import Any, Optional
import json
from .encrypt_util import EncryptUtil


class Transcryptor:
    def __init__(self):
        self.web3_provider: Optional[Any] = None
        self.web3: Optional[Web3] = None
        self.encryption_public_key: Optional[str] = None
        self.ready = self._init()

    async def _init(self) -> None:
        """Initialize Web3 connection"""
        # For Python web3, we'll typically use HTTP or WebSocket provider
        # Note: window.ethereum equivalent would need to be handled differently
        # in a Python web context (e.g., through a web framework)

        try:
            # In a production environment, you'd want to handle provider selection
            # based on your specific needs
            self.web3_provider = Web3.HTTPProvider("http://localhost:7545")
            self.web3 = Web3(self.web3_provider)

            # Verify connection
            if not self.web3.is_connected():
                raise Exception("Failed to connect to Web3 provider")

        except Exception as error:
            print(f"Failed to initialize Web3: {error}")
            raise

    async def _get_public_key(self) -> None:
        """Retrieve the encryption public key from the ethereum account"""
        if not self.web3:
            raise Exception("Web3 not initialized")

        try:
            accounts = self.web3.eth.accounts
            if not accounts:
                raise Exception("No accounts found")

            # Create the JSON-RPC payload
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getEncryptionPublicKey",
                "params": [accounts[0]],
                "from": accounts[0],
            }

            # Send the request through the provider
            response = await self.web3.provider.make_request(
                payload["method"], payload["params"]
            )

            if "error" in response:
                raise Exception(response["error"])

            self.encryption_public_key = response["result"]

        except Exception as error:
            print(f"Failed to get public key: {error}")
            raise

    async def encrypt_public_key(self, data_obj: dict) -> HexStr:
        """
        Encrypt data using the public key

        Args:
            data_obj: Dictionary of data to encrypt

        Returns:
            HexStr: Encrypted message as hexadecimal string
        """
        await self.ready

        if not self.encryption_public_key:
            await self._get_public_key()

        data = json.dumps(data_obj)

        encrypted_data = EncryptUtil.encrypt(self.encryption_public_key, data)

        encrypted_message = self.web3.to_hex(text=json.dumps(encrypted_data))

        return encrypted_message

    async def decrypt_private_key(self, encrypted_data: str) -> str:
        """
        Decrypt data using the private key

        Args:
            encrypted_data: Encrypted data string

        Returns:
            str: Decrypted data
        """
        await self.ready

        if not self.web3:
            raise Exception("Web3 not initialized")

        try:
            accounts = self.web3.eth.accounts
            if not accounts:
                raise Exception("No accounts found")

            payload = {
                "jsonrpc": "2.0",
                "method": "eth_decrypt",
                "params": [encrypted_data, accounts[0]],
                "from": accounts[0],
            }

            response = await self.web3.provider.make_request(
                payload["method"], payload["params"]
            )

            if "error" in response:
                raise Exception(response["error"])

            return response["result"]

        except Exception as error:
            print(f"Failed to decrypt data: {error}")
            raise
