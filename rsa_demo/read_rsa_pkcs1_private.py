'''
Read a PKCS#1 (RSA) private key PEM file.

The files are of the form:

   $ cat test1a
   -----BEGIN RSA PRIVATE KEY-----
   MIIEowIBAAKCAQEApbDykF8NXU4n+Qk95qc6JR/IomdRx7G7LAVYy7+iq05/5dy+
   Ezp9lJICH9rx1wkQJiqwIqjL4hPVbupmHZqKTZlMqgQc0PwgmdRyrorBdvgbiuu3
   6dc3AGaoyCNF5q23SY8wy7VTw/shnU8rN4eOgc8Vey19IIfvGbcbZ9f4QUS8Xf4x
   75/QKAOv6FkRx/ezfdoksLpSlRa51iVM4r8TfPr3kXwmDfrRIPVqiNMB7Zv8MfGd
   iWWnjztVokRkmgCQbPuUr1M9+r48X+3zyURv50KOv+E5ztJnI+RlIik8X6/++7us
   vDZ9gyOCT80bK4RMp0v89j6aGfcRF5JJbHi2pQIDAQABAoIBAGNWn1cnZd/XB+gr
   Pk2XXSj80VFtGH7ddBaEbiRaFLEYM14g5mSo4Lm+gD+RCQWfjWsUlN1yzioRMhl5
   txdwnBLCIlCcfppdTz5rPQagcjVds0Wq5WzxdyxqYC791t7ir80OaHb5k+sgGZsy
   5/o2752sBnj/YNGsLhIA0hGETnbyQ8HJ3dJs/f8T2F1sy3qOi7Nx5gvADcEd0Z/F
   OoQl5wMtj1gNmhLu+wHj/1gVptGaogaHIuKyCgTqOtOviW/0UMtNuPvx44oMVgh3
   s7lXKffx3+f658PZIvCi29QTpgv2Xp0U7p1ueVDLCu2HQUn2fIjCsHyfO/qGGEYV
   knS2jwECgYEA1qTC7VdsrTSwR6vWcfbD6SkCl+KEAefBw9xXMXPPE4hvZZWl/L7h
   WLCldaS+YFJaZVkv2hbNDkruPWhl8moweizBZjwoKkdJRZjI+AA6O3qNf5eq0pas
   Q3Ruw5yb8Hf4jKmB4hkBfpy+8Zha9JMU3p1jWEFI8zdagJPg9wB/1pUCgYEAxZ2f
   Pde+sSPxtQEv7Qp/dSZxRpyaltORClG+TJNyVnjAF+b0j59B06XFQBpwHRBJuQgT
   nN1w+xuQ1GBEkqmV9yLdqXluKX0YB2ZXb9sA2nDaHowWTB+r63xXcu5ZB6CKXqyv
   +0Ci2iiIttCArLLqPYsm1/KmATPAvtL8MUhxq9ECgYBiaWh2KX9Kar3oHoFT/zAT
   1xm5ScH8naXZh0zy/4YSDpwEl3hjSaFIaLV0GvSudRO9JAcslwetZe2VeihD3Swc
   2ChUF4DS4ZxWrJZ4HqKUYrw9o+xOYYbZ5qhiR4u31UnANHe4kn587qEdZB1PxZ/r
   8X17GXO5D8gO675ZgYEbgQKBgQC1K4uZU9jUZ+KpkfwRMkWl7md9WAd17WKUdlqj
   s63oTu21PBzMKzJbSifrXBGa45rjEt+AOZfh7uS5f8R+PRFqsEFNpTD0wmWsKwxQ
   VRSUL1AZH0813PdtfeJiUNe4YVtZ7rGsBBcJMI4eJEtDiQetAozK//9nLL4xdBaX
   TBZCcQKBgD9flmYm2Ug9cdb4IFqJ2XYxdlrkWiSRcf56S/N08sn4RPJD6yk80PZN
   MUWFXvCwP5L4jAx5ZTzvcgDIdY7EVQsWLQMegVDUF+VKLLwHIgbB/pcjOCqnw8Yn
   hzN0EiWHguTlazmMdZ11POSTnunPGmf7JxFVyh/mq6bbEebYSd1c
   -----END RSA PRIVATE KEY-----
'''
import base64
import sys

try:
    # The right way for 3.8 and beyond.
    from collections.abc import namedtuple
except ImportError:
    from collections import namedtuple

from pyasn1.type import univ
from pyasn1.codec.der import decoder as der_decoder


# pylint: disable=too-many-locals
def read_pkcs1_prikey(path):
    '''
    Read the RSA private key file.
    '''
    with open(path, 'r') as ifp:
        first, *b64, last = ifp.readlines()
    assert first.strip() == '-----BEGIN RSA PRIVATE KEY-----'
    assert last.strip() == '-----END RSA PRIVATE KEY-----'
    b64_str = ''.join([o.strip() for o in b64])
    b64_bytes = base64.b64decode(b64_str)

    # This is decoded raw, with no structure, that is why
    # recursion is disabled.
    _, msg = der_decoder.decode(b64_bytes, asn1Spec=univ.Sequence(), recursiveFlag=False)
    version, msg = der_decoder.decode(msg, asn1Spec=univ.Integer())
    modulus, msg = der_decoder.decode(msg, asn1Spec=univ.Integer())
    pubexp, msg = der_decoder.decode(msg, asn1Spec=univ.Integer())
    priexp, msg = der_decoder.decode(msg, asn1Spec=univ.Integer())
    prime1, msg = der_decoder.decode(msg, asn1Spec=univ.Integer())
    prime2, msg = der_decoder.decode(msg, asn1Spec=univ.Integer())
    exponent1, msg = der_decoder.decode(msg, asn1Spec=univ.Integer())
    exponent2, msg = der_decoder.decode(msg, asn1Spec=univ.Integer())
    crt_coeff, _ = der_decoder.decode(msg, asn1Spec=univ.Integer())
    rec = {
        'version': version,
        'modulus': int(modulus),
        'pubexp': int(pubexp),
        'priexp': int(priexp),
        'prime1': int(prime1),
        'prime2': int(prime2),
        'exponent1': int(exponent1),
        'exponent2': int(exponent2),
        'crt_coeff': int(crt_coeff),
        }
    ntdef = namedtuple('_', sorted(rec.keys()))
    return ntdef(**rec)
# pylint: enable=too-many-locals


def main():
    '''main'''
    for path in sys.argv[1:]:
        print(f'{path}')
        rec = read_pkcs1_prikey(path)
        print(f'   version   = {rec.version}')
        print(f'   modulus   = {rec.modulus:x}')
        print(f'   pubexp    = {rec.pubexp:x}')
        print(f'   priexp    = {rec.priexp:x}')
        print(f'   prime1    = {rec.prime1:x}')
        print(f'   prime2    = {rec.prime2:x}')
        print(f'   exponent1 = {rec.exponent1:x}')
        print(f'   exponent2 = {rec.exponent2:x}')
        print(f'   crt_coeff = {rec.crt_coeff:x}')


if __name__ == '__main__':
    main()
