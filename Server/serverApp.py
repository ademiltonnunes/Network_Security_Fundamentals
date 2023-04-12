from server import Server
from RC4 import RC4Cipher
from MD import MDAlgorithm
import random

class ServerApp:
    def show_menu(self):
        print("MENU")
        print("1. ANSWER CLIENT")      
        print()

def main() -> None:
    app:ServerApp = ServerApp()
    rc4: RC4Cipher = RC4Cipher()
    md: MDAlgorithm = MDAlgorithm()
    key :str =""    
    key = input("Insert the key for comunication: ")

    if key !="":
        server :Server = Server()
        client_socket, client_address = server.connect_client()
        print(f"Connection from {client_address} has been established.")
        print()

        while True:
            try:              
                
                cipher = client_socket.recv(1024).decode()

                if cipher != '':

                    #message got from client
                    print("Message got from client")
                    print(f"Encrypted message: {cipher}")
                    message_decrypted = rc4.decryption(cipher, key)

                    #Verify integrity 
                    split_message = message_decrypted.split(",")
                    message = split_message[0]
                    hash_message = split_message[1]
                    print("Verifying Digital Signature")
                    integrity:bool = md.verify_integrity(message, hash_message)
                    

                    if integrity:
                        print("Message with integrity!")       
                        # print the received message
                        print(f"Client: {message}")
                        print()
                    else:
                        print("Message has been tampered with!")
                        client_socket.close()
                        break

                    app.show_menu()
                    command_number: int = int(input("Please, enter a command number: "))
                    if command_number == 1:

                        #generate a random number                   
                        random_num = random.randint(1, 10000)
                        response = str(random_num)
                        print(f"Random number: {response}")

                        #generate hash
                        hash = md.create_hash(response)

                        #digital signature
                        response_signed = response + ","+hash
                        print("Message Signed!")

                        #encryption
                        response_cipher = rc4.encryption(response_signed, key)
                        print(f"Encrypted: {response_cipher}")

                        # send a message to the client                  
                        client_socket.send(response_cipher.encode())
                        print("Response sent!")
                        print()  
                    else:
                        client_socket.close()
                        break 
                else:
                    break           
            except ValueError:
                print("Something went wrong in the connection.")
    else:
        print("The key you informed has a problem")

if __name__ == "__main__":
    main()
