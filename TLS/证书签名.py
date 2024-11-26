from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta


def generate_rsa_key():
    rsa_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return rsa_key

def generate_ecdsa_key():
    ecdsa_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )
    return ecdsa_key

def create_csr(private_key, common_name):
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr = csr_builder.subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
    ).sign(private_key, SHA256(), default_backend())
    return csr

def sign_certificate(ca_private_key, ca_subject_name, csr, validity_days=365, is_rsa=True):
    subject = csr.subject
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca_subject_name),
    ])
    
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(ca_private_key, SHA256(), default_backend())
    )
    
    return certificate

def save_to_file(data, filename, is_private_key=False):
    with open(filename, "wb") as f:
        if is_private_key:
            f.write(data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        else:
            f.write(data.public_bytes(serialization.Encoding.PEM))

def main():
    ca_rsa_key = generate_rsa_key()
    ca_ecdsa_key = generate_ecdsa_key()
    
    user_rsa_key = generate_rsa_key()
    user_csr = create_csr(user_rsa_key, common_name="www.example.com")
    
    ca_subject_name = "Example CA"
    rsa_signed_cert = sign_certificate(ca_rsa_key, ca_subject_name, user_csr, is_rsa=True)
    ecdsa_signed_cert = sign_certificate(ca_ecdsa_key, ca_subject_name, user_csr, is_rsa=False)
    
    save_to_file(ca_rsa_key, "ca_rsa_key.pem", is_private_key=True)
    save_to_file(ca_ecdsa_key, "ca_ecdsa_key.pem", is_private_key=True)
    save_to_file(rsa_signed_cert, "rsa_signed_cert.pem")
    save_to_file(ecdsa_signed_cert, "ecdsa_signed_cert.pem")

if __name__ == "__main__":
    main()


    #cryptography 的x509
'''
#1. 定义基础类和数据结构
   #（1）定义公钥和私钥类（基于 RSA 示例）

class RSAPrivateKey:
    def __init__(self, modulus, public_exponent, private_exponent):
        self.modulus = modulus
        self.public_exponent = public_exponent
        self.private_exponent = private_exponent

    def sign(self, data, padding, hash_algorithm):
        """
        简单模拟签名操作，实际情况更复杂
        """
        # 这里只是示意，实际需要按照对应加密算法和标准来进行计算签名
        return b'simulated_signature'


class RSAPublicKey:
    def __init__(self, modulus, public_exponent):
        self.modulus = modulus
        self.public_exponent = public_exponent

    def verify(self, signature, data, padding, hash_algorithm):
        """
        简单模拟验证签名操作，实际需要严格按照算法逻辑
        """
        # 这里只是示意判断，实际要根据加密算法和数学运算来验证
        return True
    
    #（2）定义证书主体信息类（包含常见的一些证书字段）

class X509Subject:
    def __init__(self, common_name, organization, organizational_unit, country, state, locality):
        self.common_name = common_name
        self.organization = organization
        self.organizational_unit = organizational_unit
        self.country = country
        self.state = state
        self.locality = locality

#class X509Subject:
    def __init__(self, common_name, organization, organizational_unit, country, state, locality):
        self.common_name = common_name
        self.organization = organization
        self.organizational_unit = organizational_unit
        self.country = country
        self.state = state
        self.locality = localit


        #（3）定义有效期类

class ValidityPeriod:
    def __init__(self, not_before, not_after):
        self.not_before = not_before
        self.not_after = not_after

#2. 定义证书类及相关操作函数
     #（1）定义证书类
class X509Certificate:
    def __init__(self, subject, issuer, public_key, serial_number, validity, signature):
        self.subject = subject
        self.issuer = issuer
        self.public_key = public_key
        self.serial_number = serial_number
        self.validity = validity
        self.signature = signature


        #（2）生成证书签名函数（实际要遵循严格的签名规范）
    def sign_certificate(certificate, private_key, hash_algorithm):

    # 模拟获取证书需要签名的数据部分（实际要按x509标准组装相关信息）
    data_to_sign = b'some_data_derived_from_certificate_fields'
    padding = None  # 实际需要合适的填充方式，这里简化
    return private_key.sign(data_to_sign, padding, hash_algorithm)

        #（3）验证证书签名函数（简单示意）
def verify_certificate_signature(certificate, public_key):
    """
    验证证书的签名是否有效
    """
    # 模拟获取证书需要验证的数据部分（实际按标准提取相关内容）
    data_to_verify = b'some_data_derived_from_certificate_fields'
    padding = None  # 实际需按规范，这里简化
    hash_algorithm = None  # 假设一种，实际需指定准确算法
    return public_key.verify(certificate.signature, data_to_verify, padding, hash_algorithm)
'''