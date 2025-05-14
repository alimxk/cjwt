#!/usr/bin/env python3

import jwt
import json
import os
import datetime
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import base64


def generate_sample_jwt_hs256(secret="test-secret", exp_seconds=3600):
    """Generate a sample JWT using HS256 algorithm"""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "1234567890",
        "name": "Test User",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=exp_seconds)).timestamp())
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def generate_expired_jwt_hs256(secret="test-secret", exp_seconds=-3600):
    """Generate an expired JWT using HS256 algorithm"""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "1234567890",
        "name": "Test User",
        "iat": int((now - timedelta(seconds=abs(exp_seconds) * 2)).timestamp()),
        "exp": int((now - timedelta(seconds=abs(exp_seconds))).timestamp())
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def generate_rsa_key_pair():
    """Generate RSA private and public keys"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')


def generate_ec_key_pair():
    """Generate EC private and public keys"""
    private_key = ec.generate_private_key(
        curve=ec.SECP256R1(),
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')


def generate_sample_jwt_rs256(private_key):
    """Generate a sample JWT using RS256 algorithm"""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "1234567890",
        "name": "Test User",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=3600)).timestamp())
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def generate_sample_jwt_es256(private_key):
    """Generate a sample JWT using ES256 algorithm"""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "1234567890",
        "name": "Test User",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=3600)).timestamp())
    }
    return jwt.encode(payload, private_key, algorithm="ES256")


def save_to_file(content, filename):
    """Save content to a file"""
    with open(filename, 'w') as f:
        f.write(content)


def read_from_file(filename):
    """Read content from a file"""
    with open(filename, 'r') as f:
        return f.read()


def generate_test_keys():
    """Generate and save test keys to files"""
    os.makedirs('tests/keys', exist_ok=True)
    
    # Generate RSA keys
    rsa_private_key, rsa_public_key = generate_rsa_key_pair()
    save_to_file(rsa_private_key, 'tests/keys/rsa_private.pem')
    save_to_file(rsa_public_key, 'tests/keys/rsa_public.pem')
    
    # Generate EC keys
    ec_private_key, ec_public_key = generate_ec_key_pair()
    save_to_file(ec_private_key, 'tests/keys/ec_private.pem')
    save_to_file(ec_public_key, 'tests/keys/ec_public.pem')
    
    # Generate JWK from RSA public key
    # This is a simplified version, in practice you'd use a library like authlib
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "test-key-1"
    }
    save_to_file(json.dumps(jwk), 'tests/keys/test.jwk')


def setup_test_files():
    """Create test files containing JWTs"""
    os.makedirs('tests/data', exist_ok=True)
    
    # Create a file with a valid JWT
    valid_jwt = generate_sample_jwt_hs256()
    save_to_file(valid_jwt, 'tests/data/valid_jwt.txt')
    
    # Create a file with an expired JWT
    expired_jwt = generate_expired_jwt_hs256()
    save_to_file(expired_jwt, 'tests/data/expired_jwt.txt')
    
    # Create a file with multiple JWTs
    multiple_jwts = f"{valid_jwt}\n{generate_sample_jwt_hs256()}\n{expired_jwt}"
    save_to_file(multiple_jwts, 'tests/data/multiple_jwts.txt')
    
    # RSA signed JWT
    if os.path.exists('tests/keys/rsa_private.pem'):
        rsa_private_key = read_from_file('tests/keys/rsa_private.pem')
        rsa_jwt = generate_sample_jwt_rs256(rsa_private_key)
        save_to_file(rsa_jwt, 'tests/data/rsa_jwt.txt')
    
    # EC signed JWT
    if os.path.exists('tests/keys/ec_private.pem'):
        ec_private_key = read_from_file('tests/keys/ec_private.pem')
        ec_jwt = generate_sample_jwt_es256(ec_private_key)
        save_to_file(ec_jwt, 'tests/data/ec_jwt.txt')


if __name__ == "__main__":
    generate_test_keys()
    setup_test_files() 