'''
Read a PKCS#1 (RSA) public key PEM file.

The files are of the form:

   $ cat test1a.pub.pem
   -----BEGIN RSA PUBLIC KEY-----
   MIIBCgKCAQEApbDykF8NXU4n+Qk95qc6JR/IomdRx7G7LAVYy7+iq05/5dy+Ezp9
   lJICH9rx1wkQJiqwIqjL4hPVbupmHZqKTZlMqgQc0PwgmdRyrorBdvgbiuu36dc3
   AGaoyCNF5q23SY8wy7VTw/shnU8rN4eOgc8Vey19IIfvGbcbZ9f4QUS8Xf4x75/Q
   KAOv6FkRx/ezfdoksLpSlRa51iVM4r8TfPr3kXwmDfrRIPVqiNMB7Zv8MfGdiWWn
   jztVokRkmgCQbPuUr1M9+r48X+3zyURv50KOv+E5ztJnI+RlIik8X6/++7usvDZ9
   gyOCT80bK4RMp0v89j6aGfcRF5JJbHi2pQIDAQAB
   -----END RSA PUBLIC KEY-----
'''
import base64
import sys
from typing import Tuple

from pyasn1.type import univ
from pyasn1.codec.der import decoder as der_decoder


def read_pem_rsa_pubkey(path: str) -> Tuple[int, int]:
    '''
    Read the PEM encoded file.
    '''
    # Really cheap and cheerful approach.
    with open(path, 'r') as ifp:
        first, *b64, last = ifp.readlines()
    assert first.strip() == '-----BEGIN RSA PUBLIC KEY-----'
    assert last.strip() == '-----END RSA PUBLIC KEY-----'
    b64_str = ''.join([o.strip() for o in b64])
    b64_bytes = base64.b64decode(b64_str)

    # This is decoded raw, with no structure, that is why
    # recursion is disabled.
    _, msg = der_decoder.decode(b64_bytes, asn1Spec=univ.Sequence(), recursiveFlag=False)
    modulus, msg = der_decoder.decode(msg, asn1Spec=univ.Integer())
    pubexp, _ = der_decoder.decode(msg, asn1Spec=univ.Integer())
    return int(modulus), int(pubexp)


def main() -> None:
    '''main'''
    for path in sys.argv[1:]:
        print(f'{path}')
        modulus, pubexp = read_pem_rsa_pubkey(path)
        print(f'   pubexp    = 0x{pubexp:x}')
        print(f'   modulus   = 0x{modulus:x}')


if __name__ == '__main__':
    main()
