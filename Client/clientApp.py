from client import Client
from RC4 import RC4Cipher
from MD import MDAlgorithm
import random

class ClientApp:
    def show_menu(self):
        print("MENU")
        print("1. CONTACT SERVER")
        print("2. QUIT -  Exit system")        
        print()

def main() -> None:
    app:ClientApp = ClientApp()
    rc4: RC4Cipher = RC4Cipher()
    md: MDAlgorithm = MDAlgorithm()
    key :str =""
    key = input("Insert the key for comunication: ")

    if key !="":
        client :Client = Client()
        while True:
            try:
                app.show_menu()
                command_number: int = int(input("Please, enter a command number: "))
                if command_number == 1:

                    #generate a random number                   
                    random_num = random.randint(1, 10000)
                    message = str(random_num)
                    print(f"Random number: {message}")

                    #generate hash
                    hash = md.create_hash(message)

                    #digital signature
                    message_signed = message + ","+hash
                    print("Message Signed!")

                    #encryption
                    cipher = rc4.encryption(message_signed,key)
                    print(f"Encrypted: {cipher}")

                    # send a message to the server
                    client.socket.send(cipher.encode())
                    print("Message sent!")
                    print()

                    # receive data from the server
                    response_cipher = client.socket.recv(1024).decode()
                    if response_cipher !='':
                        print("Message got from Server")
                        print(f"Encrypted response: {response_cipher}")
                        response_decrypted = rc4.decryption(response_cipher,key)

                        #Verify integrity
                        split_response = response_decrypted.split(",")
                        response = split_response[0]
                        hash_response = split_response[1]
                        print("Verifying Digital Signature")
                        integrity:bool = md.verify_integrity(response, hash_response)

                        if integrity:
                            print("Message with integrity!") 
                            print(f"Server: {response}") 
                            print()  
                        else:
                            print("Message has been tampered with!")
                            client.socket.close()
                            break
                    else:
                        client.socket.close()
                        break 
                elif command_number != 1:
                    client.socket.close()
                    break       
            except ValueError:
                print("Something went wrong in the connection.")
    else:
        print("The key you informed has a problem")

if __name__ == "__main__":
    main()
