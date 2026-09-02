from core.tls.hsm_tls import HSMTLSClient
import os
import threading


class TLSConnectionClosed(Exception):
    """Raised when the TLS connection is closed by the server."""

    pass


class TLSReconnectFailed(Exception):
    pass


class CommandUnexpectedResponse(Exception):
    pass


class CommandErrorResponse(Exception):
    pass


class TLSSocketWrapper:
    """
    TLS socket wrapper for secure client-server communication.

    Handles TLS 1.3 connection setup, PSK authentication, and
    Keystore command sending (read, write, encrypt, decrypt, etc.).
    """

    def __init__(
        self, hostname, port, servername, psk=None, ensure_connected_before_send=True
    ):
        """
        Initialize the TLS socket wrapper and SSL context.

        Args:
            servername (str): Server Name for TLS handshake.
            hostname (str): Server IP or hostname.
            port (int): Server port.
            psk (bytes): The pre-shared key value.
            ensure_connected_before_send (bool): Tries to reconnect before sending if the connection timed out

        Infos:
            30s after executing a command the server will disconnect upon the reception of another command (except for echo)
        """

        self.__hostname = hostname
        self.__port = port
        self.__servername = servername
        self.__client = None
        self.__psk = psk
        self.__ensure_connected_before_send = ensure_connected_before_send
        

    ############## Read-only instance attributes ###############
    @property
    def hostname(self):
        return self.__hostname

    @property
    def servername(self):
        return self.__servername

    # DEPRECATED
    def set_psk(self, psk):
        """
        Configure the Pre-Shared Key (PSK) used for TLS authentication.

        Args:
            psk (bytes): The pre-shared key value.
        """

        self.__psk = psk

    def connect(self):
        """
        Establish a secure TLS connection with the given server.
        Returns:
            TLSSocketWrapper: The active socket wrapper instance.
        Raises:
            Exception: If connection or TLS handshake fails.
        """
        if not self.__hostname or not self.__port:
            print("Hostname or port not set")
            raise Exception("Hostname or port not set")

        self.__client = HSMTLSClient(
            self.__hostname,
            self.__port,
            self.__servername,
            self.__psk,
        )

        self.__client.connect()

        return self

    @staticmethod
    def __check_payload_length(data: bytes | bytearray):
        if len(data) == 0:
            raise ValueError("Empty payload.")
        elif len(data) > 16 * 16:
            raise ValueError("Payload length exeeds 16 blocks.")
        elif len(data) % 16 != 0:
            raise ValueError("Payload unpadded.")

    @staticmethod
    def __check_key_index(key_index: int):
        if (key_index < 0) or (key_index > 3):
            raise ValueError("Incorrect key index.")

    def __check_record_index(record_index: int):
        if (record_index < 0) or (record_index > 31):
            raise ValueError("Incorrect record index.")

    @staticmethod
    def __xor_bytes(b1: bytes, b2: bytes) -> bytes:
        """Returns the byte-by-byte XOR of two byte sequences of the same length."""
        return bytes(a ^ b for a, b in zip(b1, b2))

    # def ensure_connected(self):
    #     """
    #     Ensure the socket stays connected. Use this before performing an action on the socket, possibly between 2 commands.
    #     """
    #     try:
    #         data = self.echo("test")
    #         if not data.startswith("test"):
    #             self._close_socket()
    #             self.connect()
    #     except Exception as e:
    #         print("Error: the keystore ", self.__servername, " might be busy")
    #         print(e)
    #         exit()

    ########## METHODS TO USE THE SOCKET ################

    def echo(self, msg: str):
        """
        Send an echo command.

        Args:
            msg (str): Message to send for testing.
        """

        data = f"?01{msg}\n".encode("utf-8")
        if not self.send_command(data).decode().startswith(msg):
            raise CommandUnexpectedResponse("Echo failed")

    def read_record(self, record_number: int) -> bytes:
        """
        Reads the string stored at the specified record number on the remote server.

        Args:
            record_number (int): The record number to read from.

        Returns:
            bytes: The data contained in the record.

        Notes:
            Reading "ERROR" will raise an exception.
        """

        TLSSocketWrapper.__check_record_index(record_number)
        data = f"I{record_number:02x}\n".encode("utf-8")
        response = self.send_command(data)
        if response.startswith(b"ERROR"):
            raise CommandErrorResponse(f"Read record n°{record_number:02x} failed")
        return response

    def write_record(self, record_number: int, data: bytes | bytearray):
        """
        Writes bytes to the specified record number on the remote server.

        Args:
            record_number (int): The record number to write to.
            data (bytes-like object): The bytes to write.
        """

        TLSSocketWrapper.__check_record_index(record_number)

        command_data = (
            f"Z{record_number:02x}".encode("utf-8") + data + "\n".encode("utf-8")
        )
        response = self.send_command(command_data).decode()
        if not response.startswith("OK"):
            if response.startswith("ERROR"):
                raise CommandErrorResponse(f"Write record n°{record_number:02x} failed")
            else:
                raise CommandUnexpectedResponse(
                    f"Unexpected response from server: {response}"
                )

    def set_AES_key(self, index_key: int, key: bytes | bytearray):
        """
        Define a new AES key on the Keystore.

        Args:
            index_key (int): Key index (00–03).
            key (bytes | bytearray): 16 bytes AES key.
        """

        TLSSocketWrapper.__check_key_index(index_key)
        text_key = key.hex()
        data = f"t{index_key:02x}{text_key}\n".encode("utf-8")
        response = self.send_command(data).decode()
        if not response.startswith("OK"):
            if response.startswith("ERROR"):
                raise CommandErrorResponse(f"Set key n°{index_key:02x} failed")
            else:
                raise CommandUnexpectedResponse(
                    f"Unexpected response from server: {response}"
                )

    def encrypt_AES(self, index_key: int, data: bytes | bytearray) -> bytes:
        """
        Encrypt data using the AES key at the specified index.

        Args:
            index_key (int): Key index (0–3).
            data (bytes | bytearray): Data to encrypt, 1 to 16 blocks of 16 bytes.
        """

        TLSSocketWrapper.__check_payload_length(data)
        TLSSocketWrapper.__check_key_index(index_key)

        text_data = data.hex()
        text_command = f"A4{index_key:x}{text_data}\n".encode("utf-8")
        response = self.send_command(
            text_command
        ).decode()  # We decode text encoded hex.
        if response.startswith("ERROR"):
            raise CommandErrorResponse(
                f"Encrypting using AES key n°{index_key:x} failed"
            )
        return bytes.fromhex(response)  # We encode hex text to python bytes.

    def decrypt_AES(self, index_key: int, data: bytes | bytearray) -> bytes:
        """
        Decrypt data using the AES key at the specified index.

        Args:
            index_key (int): Key index (0–3).
            data (bytes | bytearray): Data to decrypt, 1 to 16 blocks of 16 bytes.
        """

        TLSSocketWrapper.__check_payload_length(data)
        TLSSocketWrapper.__check_key_index(index_key)

        text_data = data.hex()
        text_command = f"a4{index_key:x}{text_data}\n".encode("utf-8")
        response = self.send_command(text_command).decode()
        if response.startswith("ERROR"):
            raise CommandErrorResponse(
                f"Decrypting using AES key n°{index_key:x} failed"
            )
        return bytes.fromhex(response)

    def encrypt_AES_binary(self, index_key: int, data: bytes | bytearray) -> bytes:
        """
        Encrypt data using the AES key at the specified index.

        Args:
            index_key (int): Key index (0–3).
            data (bytes-like object): Data to encrypt.
        """

        TLSSocketWrapper.__check_payload_length(data)
        TLSSocketWrapper.__check_key_index(index_key)

        command_data = f"Ac{index_key:1X}".encode("utf-8") + data + "\n".encode("utf-8")
        try:
            response = self.send_command(command_data)
        except TLSConnectionClosed as e:
            raise CommandErrorResponse("Encryption failed.")
        return response

    def decrypt_AES_binary(self, index_key: int, data: bytes | bytearray) -> bytes:
        """
        Decrypt data using the AES key at the specified index.

        Args:
            index_key (int): Key index (0–3).
            data (bytes-like object): Data to decrypt.
        """

        TLSSocketWrapper.__check_payload_length(data)
        TLSSocketWrapper.__check_key_index(index_key)

        command_data = f"ac{index_key:1X}".encode("utf-8") + data + "\n".encode("utf-8")
        try:
            response = self.send_command(command_data)
        except TLSConnectionClosed as e:
            raise CommandErrorResponse("Decryption failed.")
        return response

    def wrap_cek(self, index_key: int, key: bytes | bytearray) -> bytes:
        r = os.urandom(16)
        r1 = int.from_bytes(r, byteorder="big") + 1
        r1 = r1.to_bytes(16, byteorder="big")
        r2 = int.from_bytes(r, byteorder="big") + 2
        r2 = r2.to_bytes(16, byteorder="big")

        eval1 = self.encrypt_AES_binary(index_key, r1)
        eval2 = self.encrypt_AES_binary(index_key, r2)

        k1, k2 = key[:16], key[16:]
        c1 = TLSSocketWrapper.__xor_bytes(eval1, k1)
        c2 = TLSSocketWrapper.__xor_bytes(eval2, k2)
        ck = b"".join((r, c1, c2))
        return ck

    def unwrap_cek(self, index_key: int, ck: bytes | bytearray) -> bytes:
        r = ck[:16]

        r1 = int.from_bytes(r, byteorder="big") + 1  # Convertit r en entier
        r1 = r1.to_bytes(16, byteorder="big")  # Reconvertit en bytes (16 octets)
        r2 = int.from_bytes(r, byteorder="big") + 2
        r2 = r2.to_bytes(16, byteorder="big")

        eval1 = self.encrypt_AES_binary(index_key, r1)
        eval2 = self.encrypt_AES_binary(index_key, r2)

        k1 = TLSSocketWrapper.__xor_bytes(ck[16:32], eval1)
        k2 = TLSSocketWrapper.__xor_bytes(ck[32:], eval2)
        k = k1 + k2

        return k

    def close(self):
        """
        Send a termination command and close the TLS socket.
        """

        data = "?02\n".encode("utf-8")
        self.__client.send(data)
        self.__client.close()

    def _close_socket(self):
        """
        Close the TLS socket
        """

        self.__client.close()

    def receive_command_bytes(self):
        """
        Receive raw data from the TLS socket.

        Returns:
            bytes: Data received from the server.
        """
        data = self.__client.recv(4096)
        if data == b"":
            raise TLSConnectionClosed("Server closed connection (EOF).")
        return data

    def send_command(self, data: bytes | bytearray) -> bytes:
        """
        Send raw data from the TLS socket.

        Arguments:
            data (bytes-like object): Command to send.
        Returns:
            bytes: Data received from the server.
        Raises:
            TLSConnectionClosed: if the server closed the connection and auto-reconnect is disabled.
            TLSReconnectFailed: if reconnection or resend fails.
        """

        # TODO add a try block to ensure connection (no close socket in the except)
        self.__client.send(data)
        try:
            response = self.receive_command_bytes()
        except TLSConnectionClosed:
            if self.__ensure_connected_before_send:
                print("Info: reconnecting before sending data")
                try:
                    self._close_socket()
                    self.connect()
                    self.__client.send(data)
                    response = self.receive_command_bytes()
                except Exception as e:
                    raise TLSReconnectFailed(
                        f"Reconnection to {self.__servername} failed: {e}"
                    ) from e
                # print("Warning: auto reconnecting the socket upon server timeout which is monopolizing resources")
            else:
                raise TLSConnectionClosed(
                    "Server closed the connection (auto-reconnect disabled)."
                )
        return response

    def __str__(self):
        return (
            self.__hostname
            + str(self.__port)
            + str(self.__servername)
            + str(self.__client)
            + str(self.__psk)
        )
