#!/usr/bin/env python3
# caesar.py
# Caesar Cipher
"""A Python script to encrypt or decrypt text according to a shift value"""


def encrypt(s):  # Function for encrypting the text
    print('\nEncrypted text output :', end=' ')
    for x in s:  # Repeating the loop for each character in the string
        if x.isalpha():  # Check if the chracter is an alphabet (irrespective of the case)
            var = n + ord(x)  # If True, then process the ASCII value of the shifted character
            if var > 90:
                var -= 26
            elif var < 65:
                var += 26
            print(chr(var), end='')  # And print the shifted character
        else:
            print(x, end='')  # Else print the character as it is

    print('\n')


def decrypt(s):  # Function for decrypting the text
    print('\nDecrypted text output :', end=' ')
    for x in s:  # Repeating the loop for each character in the string
        if x.isalpha():  # Check if the chracter is an alphabet (irrespective of the case)
            var = ord(x)-n  # If True, then process the ASCII value of the shifted character
            if var > 90:
                var -= 26
            elif var < 65:
                var += 26

            print(chr(var), end='')  # And print the shifted character
        else:
            print(x, end='')  # Else print the character as it is

    print('\n')


print('\n\tCaeser Cipher Encrypter/Decrypter')
while True:  # Running as long as the user wants
    try:
        print('[+] Options :\n\t1.) Encrypt Text\n\t2.) Decrypt Text')
        print('\tPress Ctrl+C to exit.')
        try:
            ch = int(input('[+] Enter your choice (1/2) : '))  # Taking choice as the input
        except ValueError:  # If the input is not an integer (1 or 2), run the loop again
            print('[!] Invalid input. Try again.\n')
            continue

        if ch == 1:
            text = input('[+] Input text : ')  # Input string/text
            text = text.upper()  # Converting the text to uppercase
            try:
                n = int(input('[+] Enter offset : '))  # Input shift value for encryption
                if n >= 26 or n <= -26:  # Shift should be in the range of [-26,26]
                    print('[!] Invalid Input. Enter a number between -25 to 25\n')
                else:
                    encrypt(text)  # Calling the encryption function
            except ValueError:  # If the shift value is not an integer, throw error
                print('[!] Invalid Input.\n')
        elif ch == 2:
            text = input('[+] Input text : ')  # Input string/text
            text = text.upper()  # Converting the text to uppercase
            try:
                n = int(input('[+] Enter offset : '))  # Input shift value for decryption
                if n >= 26 or n <= -26:  # Shift should be in the range of [-26,26]
                    print('[!] Invalid Input. Enter a number between -25 to 25\n')
                else:
                    decrypt(text)  # Calling the decryption function
            except ValueError:  # If the shift value is not an integer, throw error
                print('[!] Invalid Input.\n')
        else:
            print('[!] Invalid choice.\n')
    except (EOFError, KeyboardInterrupt):  # If the user presses Ctrl+C (keyboard interruption)
        print('\n[!] Exiting...')  # Exit the loop
        break

# Exiting the program
exit()
