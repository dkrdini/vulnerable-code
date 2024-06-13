# vulnerable_code.py

import subprocess
import pickle
import hashlib


# Command Injection Vulnerability
def unsafe_command(user_input):
    subprocess.call(user_input, shell=True)


# Insecure Deserialization Vulnerability
def unsafe_deserialize(data):
    return pickle.loads(data)


# Hardcoded Password Vulnerability
def authenticate(password):
    hardcoded_password = "supersecret"  # Hardcoded password
    return password == hardcoded_password


# Insufficient Hashing Vulnerability
def store_password(password):
    # Using MD5 for password hashing, which is considered insecure
    return hashlib.md5(password.encode()).hexdigest()


def main():
    # Command Injection
    user_command = input("Enter a command: ")
    unsafe_command(user_command)

    # Insecure Deserialization
    pickled_data = input("Enter pickled data: ")
    print(unsafe_deserialize(pickled_data))

    # Hardcoded Password
    user_password = input("Enter your password: ")
    if authenticate(user_password):
        print("Authenticated successfully")
    else:
        print("Authentication failed")

    # Insufficient Hashing
    new_password = input("Enter a new password to store: ")
    hashed_password = store_password(new_password)
    print(f"Stored hashed password: {hashed_password}")


if __name__ == "__main__":
    main()
