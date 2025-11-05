import hashlib

def hash_password(password: str) -> str:
    return hashlib.sha3_256(password.encode()).hexdigest()

def check_login(input_pass: str, stored_hash: str) -> bool:
    return hash_password(input_pass) == stored_hash