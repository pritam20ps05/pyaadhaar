import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, types

# Basic functions for Cryptographic verification

def verifyBypk(data: bytes, signature: bytes, public_key: types.PublicKeyTypes) -> bool:
    """
    Verifies the signature of the Aadhaar QR code against the provided public key. 
    Using SHA256 as the hashing algorithm and PKCS1v15 padding.

    - Data: The signed data extracted from the QR code.
    - Signature: The signature extracted from the QR code.
    - Public Key: The public key for verification.

    Returns True if the signature is valid, False otherwise.
    """

    # Type checks for input parameters
    if not isinstance(data, bytes) or not isinstance(signature, bytes):
        raise ValueError("Data and signature must be bytes.")
    
    if not isinstance(public_key, types.PublicKeyTypes):
        raise ValueError("Public key must be a valid public key type of cryptography module.")
    
    # Try verifying the qr signed data bytes
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    
def getPKfromCert(cert_path: str) -> types.CertificatePublicKeyTypes:
    """
    Extracts the public key from a given certificate file.

    - cert_path: Path to the certificate file (in PEM or DER format).

    Returns the public key extracted from the certificate.
    """
    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")
    
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        try:
            # Load the certificate
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        except ValueError:
            # If PEM loading fails, try DER
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
        
        return cert.public_key()

def getPKfromFile(public_key_path: str) -> types.PublicKeyTypes:
    """
    Extracts the public key from a given public key file.

    - public_key_path: Path to the public key file (in PEM or DER format).

    Returns the public key extracted from the file.
    """
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"Public key file not found: {public_key_path}")
    
    with open(public_key_path, "rb") as pk_file:
        pk_data = pk_file.read()
        try:
            # Load the public key
            public_key = serialization.load_pem_public_key(pk_data, backend=default_backend())
        except ValueError:
            # If PEM loading fails, try DER
            public_key = serialization.load_der_public_key(pk_data, backend=default_backend())
        
        return public_key
    


