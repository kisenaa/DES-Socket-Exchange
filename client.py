import socket
import struct
from DES import Des
from RSA import RSA_Algorithm

Local_keys = ""
server_Keys = ""

class RSA_Container():
    def __init__(self) -> None:
        self.public_key: tuple[int, int] = None
        self.private_key: tuple[int, int] = None

class ClientProgram():
    def __init__(self) -> None:
        self.host                = socket.gethostname()
        self.port                = 5022
        self.client_socket       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_keys : bytes  = '\0'
        self.server_keys: bytes  = '\0'
        self.server_ip           = ""
        self.server_port         = ""
        self.DES                 = Des()
        self.RSA                = RSA_Algorithm()
        self.local_RSA          = RSA_Container()
        self.server_RSA         = RSA_Container()

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
    
    def __StartSocket(self):
        self.client_socket.connect((self.host, self.port)) 
        self.server_ip, self.server_port = self.client_socket.getpeername()
        print(f"Connected to server at IP: {self.server_ip}, Port: {self.server_port}")

        # Additional Validation
        confirmation = input("Do you want to accept this server connection? (yes/no): ")
        if confirmation.lower() == 'no' :
            print("Connection Refused ! Terminating Connection ...")
            self.client_socket.close()
            return False
        else :
            print("Connection Accepted !")
            True
    
    def __HandleMessage(self):
        # Handle Incoming / Outgoing Message
        message = input(" -> ") 

        while message.strip() != 'bye':
            # Encrypt the string before send to server
            message = message.encode('utf-8')  
            encrypted_message = self.DES.Encrypt(message, self.local_keys)
            self.client_socket.send(encrypted_message.hex().encode()) 

            # Listen to response
            data = self.client_socket.recv(1024).decode()

            # Decrypt the encrypted message from server
            print('\nRaw from server: ' + str(data))
            encrypted_message = bytes.fromhex(data)
            data = self.DES.Decrypt_using_key(encrypted_message, self.server_keys)

            print('Decrypted from server: ' + str(data))
            message = input(" -> ")

        self.client_socket.close()
    
    def Start(self):
        if self.__StartSocket() == False:
            return
        
        # Receive Server RSA keys from server
        print("Waiting for server to send it's RSA Public Key...")
        server_data = self.client_socket.recv(1024)
        self.server_RSA.public_key = self.unpack_tuple(server_data)
        print(f"Server RSA : ", self.server_RSA.public_key, '\n')

        # Send our RSA Keys to server
        print("Sending our RSA Public key to server....")
        self.local_RSA.public_key, self.local_RSA.private_key = self.RSA.generate_keypair()
        self.client_socket.send(self.pack_tuple(self.local_RSA.public_key))
        print(f"Local RSA : ", self.local_RSA.public_key, '\n')

        # Generate Random DES Keys and Send It to server . Encrypt using server public keys
        print("Sending our encrypted Local DES Key using server public RSA Key (Encrypted and Secure)...")
        self.local_keys = self.DES.Random_Bytes(8)
        encrypted_local = self.RSA.encrypt(self.local_keys.hex(), self.server_RSA.public_key)
        self.client_socket.send(self.pack_rsa(encrypted_local))
        print(f"Local DES Key: ", self.local_keys, '\n')

        # Wait for the server to send us server keys
        print("Waiting for Server to send it's DES Key using our RSA Public Key (Encrypted and Secure)...")
        server_data = self.client_socket.recv(1024)
        encrypted_serverKey = self.unpack_rsa(server_data)
        self.server_keys = bytes.fromhex(self.RSA.decrypt(encrypted_serverKey, self.local_RSA.private_key))
        print(f"Server DES Key: ", self.server_keys, '\n')

        self.__HandleMessage()


if __name__ == '__main__':
    Program = ClientProgram()
    Program.Start()


# Keys are distributed and exchange using secure RSA Keys

# 1. Client send keys -> Server receive keys
# 2. Server send keys -> Client receive key

# 1. Client encrypt -> Server Decrypt
# 2. Server Encrypt -> Client Decrypt