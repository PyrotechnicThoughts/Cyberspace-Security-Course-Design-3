from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair():
    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 序列化私钥并保存到文件
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("private.pem", "wb") as f:
        f.write(private_pem)

    # 生成公钥
    public_key = private_key.public_key()

    # 序列化公钥并保存到文件
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("public.pem", "wb") as f:
        f.write(public_pem)

    print("RSA 密钥对生成完毕：私钥保存在 private.pem，公钥保存在 public.pem")

if __name__ == "__main__":
    generate_rsa_key_pair()
