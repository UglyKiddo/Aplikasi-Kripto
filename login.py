import hashlib

def hash_password(password: str) -> str:
    return hashlib.sha3_384(password.encode()).hexdigest()

def check_login(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash