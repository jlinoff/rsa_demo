'''
Read a ssh public key file and print the fields.

The files are of the from:

   $ cat test1a.pub
   ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClsPKQXw1dTif5CT3mpzolH8iiZ1HHs
   bssBVjLv6KrTn/l3L4TOn2UkgIf2vHXCRAmKrAiqMviE9Vu6mYdmopNmUyqBBzQ/CCZ1H
   KuisF2+BuK67fp1zcAZqjII0XmrbdJjzDLtVPD+yGdTys3h46BzxV7LX0gh+8Ztxtn1/h
   BRLxd/jHvn9AoA6/oWRHH97N92iSwulKVFrnWJUzivxN8+veRfCYN+tEg9WqI0wHtm/wx
   8Z2JZaePO1WiRGSaAJBs+5SvUz36vjxf7fPJRG/nQo6/4TnO0mcj5GUiKTxfr/77u6y8N
   n2DI4JPzRsrhEynS/z2PpoZ9xEXkklseLal jlinoff@ew-mbp-dejl01.local
'''
import base64
import struct
import sys


def read_ssh_rsa_pubkey(path: str) -> [str, int, int]:
    '''
    Read the SSH RSA public key file.
    '''
    with open(path, 'r') as ifp:
        data_str = ifp.readlines()[0].split(None)[1]
    data = base64.b64decode(data_str)
    fields = []
    while data:
        # len fld is always 4 bytes
        dlen = struct.unpack('>I', data[:4])[0]
        val = data[4:dlen+4]
        data = data[4+dlen:]
        fields.append((dlen, val))
    assert len(fields) == 3
    alg = fields[0][1]
    pubexp = int.from_bytes(fields[1][1], byteorder='big')
    modulus = int.from_bytes(fields[2][1], byteorder='big')
    return str(alg, 'utf-8'), pubexp, modulus


def main():
    '''main'''
    for path in sys.argv[1:]:
        print(f'{path}')
        alg, pubexp, modulus = read_ssh_rsa_pubkey(path)
        print(f'   algorithm = {alg}')
        print(f'   pubexp    = 0x{pubexp:x}')
        print(f'   modulus   = 0x{modulus:x}')


if __name__ == '__main__':
    main()
