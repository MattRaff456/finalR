import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def encrypt_file(key): #Encrypt files
    while True:
        fileName = input('Enter the file you want encrypted along with the extension:')
        if fileName.__contains__('.'): #If the filename entered has an extension, break out of the loop.
            break

    f = Fernet(key)
    try:
        with open(fileName, "rb") as file:
            fileData = file.read()
            encrypted_file = f.encrypt(fileData) #Encrypted the data inside the file
    
        with open(fileName, "wb") as file:
            file.write(encrypted_file) #Overwrite the file to encrypt it.

    except FileNotFoundError:
        print("The file was not found! ")

def decrypt_file(key): #Decrypt files
    while True:
        fileName = input('Enter the file you want decrypted along with the extension:')
        if fileName.__contains__('.'):
            break

    f = Fernet(key)
    try:
        with open(fileName, "rb") as file:
            fileData = file.read()
            decrypted_file = f.decrypt(fileData)

        with open(fileName, "wb") as file:
            file.write(decrypted_file)

    except FileNotFoundError:
        print("The file was not found! ")

def get_text(): #Get a message to encrypt and decrypt
    text = input('Enter the message you want encrypted: ')

def make_key(): #Make a Fertnet key
    randomKey = Fernet.generate_key()
    with open("keys.key", "wb") as keys: #Open the file keys.key and write the randomKey into it.
        keys.write(randomKey)

def get_key(): #Get the key made by Fertnet
    return open("keys.key", "rb").read() #Returns the key located in the file keys.key.

def encrypt_message(message, key): #Encrypt a message
    message = message.encode()
    f = Fernet(key)
    return f.encrypt(message)

def decrypt_message(emessage, key): #Decrypt a message
    f = Fernet(key)
    return f.decrypt(emessage)

#example of encrypting and decrypting a message
'''make_key() #Encrypt and decrypt a string message
encrypt = encrypt_message("Once upon a time ", get_key())
print(encrypt)
print(decrypt_message(encrypt, get_key()))'''

#example of encrypting and decrypting a file
'''make_key() #Encrypt and decrypt a file
key = get_key()
encrypt_file(key)
decrypt_file(key)'''