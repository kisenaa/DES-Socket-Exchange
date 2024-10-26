import socket
import struct
from DES import Des
from RSA import RSA_Algorithm

Local_keys = ""
client_Keys = ""

class RSA_Container():
    def __init__(self) -> None:
        self.public_key: tuple[int, int] = None
        self.private_key: tuple[int, int] = None


class ServerProgram():
    def __init__(self) -> None:
        self.host           = socket.gethostname()
        self.port           = 5022
        self.server_socket  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection     = None
        self.client_address = ""
        self.local_keys     = ""
        self.client_keys:bytes    = ""
        self.DES            = Des()
        self.RSA            = RSA_Algorithm()
        self.local_RSA      = RSA_Container()
        self.client_RSA         = RSA_Container()

    @staticmethod
    def pack_tuple(int_tuple: tuple[int, int]) -> bytes:
        return struct.pack('qq', *int_tuple) 

    @staticmethod
    def unpack_tuple(packed_data: bytes) -> tuple[int, int]:
        return struct.unpack('qq', packed_data)
    
    @staticmethod
    def pack_rsa(encrypted_message):
        return struct.pack(f'<{len(encrypted_message)}Q', *encrypted_message)

    @staticmethod
    def unpack_rsa(packed_message):
        num_integers = len(packed_message) // 8 
        return list(struct.unpack(f'<{num_integers}Q', packed_message))

    def __StartServerSocket(self):
        self.server_socket.bind((self.host, self.port)) 
        self.server_socket.listen(1)

        self.connection, self.client_address = self.server_socket.accept()
        print("Connection from: " + str(self.client_address))

        # Additional Validation
        confirmation = input("Do you want to accept this client connection? (yes/no): ")
        if confirmation.lower() == 'no' :
            print("Connection Refused ! Terminating Connection ...")
            self.connection.close()
            return False
        else :
            print("Connection Accepted !")
            True
    
    def __HandleMessage(self):
        # Handle Incoming / Outgoing Message
        while True:
            data = self.connection.recv(1024).decode()
            if not data:
                break

            # Decrypt the encrypted message from client. Convert to bytes from hex
            print("\nRaw from client: " + str(data))
            encrypted_message = bytes.fromhex(data)
            data = self.DES.Decrypt_using_key(encrypted_message, self.client_keys)

            print("decrypted from client: " + str(data))
            data = input(' -> ')

            # Encrypt the string before sending to client
            data = data.encode('utf-8')  
            encrypted_message = self.DES.Encrypt(data, self.local_keys)

            # send data to the client
            self.connection.send(encrypted_message.hex().encode())

        self.connection.close() 
    
    def Start(self):
        if self.__StartServerSocket() == False:
            return
        
        # Generate RSA key and Send to client
        print("Sending our RSA Public Key to client...")
        self.local_RSA.public_key, self.local_RSA.private_key = self.RSA.generate_keypair()
        self.connection.send(self.pack_tuple(self.local_RSA.public_key))
        print(f"Local RSA : ", self.local_RSA.public_key, '\n')

        # Receive client RSA keys from client
        print("Waiting for client to send it's RSA Public Key...")
        client_data = self.connection.recv(1024)
        self.client_RSA.public_key = self.unpack_tuple(client_data)
        print(f"Client RSA : ", self.client_RSA.public_key, '\n')

        # Receive DES keys from client and decrypt it
        print("Waiting for client to send it's DES Key using our RSA Public Key (Encrypted and Secure)...")
        client_data = self.connection.recv(1024)
        encrypted_clientKey = self.unpack_rsa(client_data)
        self.client_keys = bytes.fromhex(self.RSA.decrypt(encrypted_clientKey, self.local_RSA.private_key))
        print(f"Client DES Key: ", self.client_keys, '\n')

        # Our turn to send our local keys to client
        print("Sending our encrypted Local DES Key using client public RSA Key (Encrypted and Secure)...")
        self.local_keys = self.DES.Random_Bytes(8)
        encrypted_local = self.RSA.encrypt(self.local_keys.hex(), self.client_RSA.public_key)
        self.connection.send(self.pack_rsa(encrypted_local))
        print(f"Local DES Key: ", self.local_keys, '\n')

        self.__HandleMessage()


if __name__ == '__main__':
    Program = ServerProgram()
    Program.Start()


# Keys are distributed and exchange using secure RSA Keys

# 1. Client send keys -> Server receive keys
# 2. Server send keys -> Client receive key

# 1. Client encrypt -> Server Decrypt
# 2. Server Encrypt -> Client Decrypt
