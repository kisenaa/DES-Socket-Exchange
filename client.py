import socket
from DES import Des

Local_keys = ""
Remote_Keys = ""

class ClientProgram():
    def __init__(self) -> None:
        self.host                = socket.gethostname()
        self.port                = 5022
        self.client_socket       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_keys : bytes  = '\0'
        self.remote_keys: bytes  = '\0'
        self.server_ip           = ""
        self.server_port         = ""
        self.DES                 = Des()
    
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
            data = self.DES.Decrypt_using_key(encrypted_message, self.remote_keys)

            print('Decrypted from server: ' + str(data))
            message = input(" -> ")

        self.client_socket.close()
    
    def Start(self):
        if self.__StartSocket() == False:
            return
        
        # Generate Random DES Keys and Send It to server
        self.local_keys = self.DES.Random_Bytes(8)
        self.client_socket.send(self.local_keys.hex().encode())
        print(f"local keys: ", self.local_keys)

        # Wait for the server to send us server keys
        self.remote_keys = self.client_socket.recv(1024).decode()
        self.remote_keys = bytes.fromhex(self.remote_keys)
        print(f"server keys: ", self.remote_keys, '\n')

        self.__HandleMessage()


if __name__ == '__main__':
    Program = ClientProgram()
    Program.Start()



# 1. Client send keys -> Server receive keys
# 2. Server send keys -> Client receive key

# 1. Client encrypt -> Server Decrypt
# 2. Server Encrypt -> Client Decrypt