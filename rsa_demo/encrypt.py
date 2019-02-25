'''
Encrypt input file using the RSA algorithm and public key file to
create a base64 encoded output file.

Note that one would normally not use RSA to encrypt a large data file
because it is significantly slower thn symmetric key encryption
algorithms. Instead, one might use RSA to encrypt a symmetric key that
is used to encrypt/decrypt data.

It will accept an SSH public key file or a PKCS#1 (RSA) PEM encoded
public key file.

The SSH public key file looks something like this:

   $ cat test.pub
   ssh-rsa AAAAB3NzaC1yc... jlinoff@ew-mbp-dejl01.local

The PEM encoded file looks like this.

   $ cat test.pub.pem
   -----BEGIN RSA PUBLIC KEY-----
   MIIBCgKCAQEAlO2zMeOpyQEm2O3dYSnKrQogi+OwUOtL9MyaQSMndTPD2FgUAcUO
   eulF6Js0XM9JSzSPZBzXALWeFMsq1/7yIq/hOw4LMHkN1CCcN7sjwD9B+vox6fdi
   pvwAoNenj8srNV7yoaKTDe1sqm9cXq1M/nih/I4siajUEKSJvmdEIT/ZSSMdGmEj
   I3vQEBHVisAtcx53Hl25atAS3Q+IbeOx8GvkHI0N2TvDhSAZrD6zKseRLjfq0EZI
   TeMmfcWHZidaVYS0NvJm3V6unA+ZOGLR+g3nYzyrbIxX1jYWTvV/knyO9uZxGI1k
   KTrFhxOleY8ADGhLcN4O8qVP5GNuE45OVwIDAQAB
   -----END RSA PUBLIC KEY-----

Other more general formats are straightforward to add but since this
is not meant to be a general purpose utility it made no sense to do
that.

The standard output is PEM like and looks like this:

   -----BEGIN JOES RSA ENCRYPTED DATA-----
   obnuYiLU9JMD0fWa1vr31V4q0L/19gWFXItRqBglbTktRrmoVpPfcN5/v2oc2IBp
   fqK85TVFZUdmz7FSG0umzdLQtHZ5yd/k3QfmKxDIi7oiy4Ui/MLFljZieDo4N+OP
   A3EZ+dc+YFtlauC2pw+iKMje6ECoOoW/vhvIInrnn80hZP5IAlChn0Y084+Ax+j/
   OphOXJyfYNS5HI/+NUruLauQQMsreNUx6yQt9UfZYfhO1J53bdh6PmOAodxwDtuB
   tZwse+gxjfd3/bHtSoP9OW1T1S/q0Uhdfll0wrRkbNn8qjAWsB60GWOgMWBSX16z
   npmi+anEvZyAutmmN0l28Jw09OCowWG0vkdxS6xBWCOoZXysw5vb2Smu48DPQy+L
   LbZRu+I2kkojrdg4U286ZwqYMiZb7LLxhNNHCrauULWY4eq674cke4ypClIL2iqa
   dByW6PXjPxSMhvueKlOjYrDlukYj+zOxR8LTOQ/JCXWQ276Rql4zkBgVOm21UpB8
   M+0ACqhE7L2+QrHFBiaXaI9fistqQ37iNrx2QJTEMrvt3VJkMHZ4FZ8D8rg9Ui9D
   U27bhOG1c/zoPEHaUTGq/7WNoFJ6awazA2AcGB5iR/LIWnPWfpsPwiD7EY0rBNih
   dvAhF7YJ3l4xgKH8d6tOl1DzEWu81V7BA0T3Mm56RoMAZQ==
   -----END JOES RSA ENCRYPTED DATA-----

There is an option to output the data in raw binary format as well.

The format of the data is a custom format that has the following
parts to make decryption easier by allowing invalid formats to
be recognized quickly:

   id              : [0-7] 8 bytes - "joes-rsa"
   version         : [8-9] 2 bytes (0), big-endian
   padding         : [10-11] 2 bytes, size of padding big-endian
   ciphertext      : [12:] bytes of encrypted data

This is, obviously, not a standard format but it it simple enough
to use for pedagological purposes.
'''
import argparse
import base64
import math
import os
import random
import struct
import sys
import textwrap

from pyasn1.type import univ
from pyasn1.codec.der import decoder as der_decoder

# Is the sys.path.append really needed?
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from rsa_demo import __version__
from rsa_demo.utils import err, infov, infovv


def getopts() -> argparse.Namespace:
    '''
    Get the command line options.
    '''
    def gettext(string):
        '''
        Convert to upper case to make things consistent.
        '''
        lookup = {
            'usage: ': 'USAGE:',
            'positional arguments': 'POSITIONAL ARGUMENTS',
            'optional arguments': 'OPTIONAL ARGUMENTS',
            'show this help message and exit': 'Show this help message and exit.\n ',
        }
        return lookup.get(string, string)

    argparse._ = gettext  # to capitalize help headers
    base = os.path.basename(sys.argv[0])
    #name = os.path.splitext(base)[0]
    usage = '\n  {0} [OPTIONS]'.format(base)
    desc = 'DESCRIPTION:{0}'.format('\n  '.join(__doc__.split('\n')))
    epilog = f'''\
EXAMPLES:
    # Example 1: help
    $ {base} --help

    # Example 2: RSA encrypt a file
    $ {base} -k test01.pub -i plaintext -o ciphertext

    # Example 3: RSA encrypt a file keep the binary format.
    $ {base} -k test01.pub -i plaintext -o ciphertext -b
'''

    afc = argparse.RawTextHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=afc,
                                     description=desc[:-2],
                                     usage=usage,
                                     epilog=epilog + ' \n')

    parser.add_argument('-b', '--binary',
                        action='store_true',
                        help='''\
Do not base64 encode the output.
Generate a binary file.

''')

    parser.add_argument('-i', '--input',
                        action='store',
                        type=str,
                        metavar=('FILE'),
                        help='''\
The file to encrypt.

''')

    parser.add_argument('-k', '--key',
                        action='store',
                        required=True,
                        type=str,
                        metavar=('FILE'),
                        help='''\
The public key file. Two formats are supported:

   1. SSH RSA public key format.
   2. PKCS#1 (RSA) PEM public key format.

The program figures out the format.

''')

    parser.add_argument('-o', '--output',
                        action='store',
                        type=str,
                        metavar=('FILE'),
                        help='''\
The encrypted file.
The default is stdout.

''')

    parser.add_argument('-s', '--seed',
                        action='store',
                        type=int,
                        help='''\
Specify a random seed. This helps with demo's but
is not at all secure.

''')

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='''\
Output a lot of information about the intermediate steps.

''')

    parser.add_argument('-V', '--version',
                        action='version',
                        version='%(prog)s version {0}'.format(__version__),
                        help='''\
Show program's version number and exit.
''')

    opts = parser.parse_args()
    return opts


def read_pem_rsa_pubkey(path: str) -> [int, int]:
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


def read_public_key_file(opts: argparse.Namespace, path: str) -> [int, int]:
    '''
    Figure out which type of file this is and read it.
    '''
    infov(opts, f'opening key file: {path}')
    with open(path, 'r') as ifp:
        data = ifp.read()
    if '-----BEGIN RSA PUBLIC KEY-----' in data:
        infov(opts, f'key type: PKCS#1 (RSA) PEM public key file')
        return read_pem_rsa_pubkey(path)
    if 'ssh-rsa' in data:
        infov(opts, f'key type: SSH RSA public key file')
        _, pub, mod = read_ssh_rsa_pubkey(path)
        return mod, pub
    err(f'unrecognized file format in {path}.')


def read_input(opts: argparse.Namespace) -> bytearray:
    '''
    Read the input data.

    There are two possible sources:
       1. A file specified by the -i option.
       2. stdin.

    In both cases, all data is read into memory which
    limits the file size to available memory.
    '''
    if opts.input:
        with open(opts.input, 'rb') as ifp:
            return ifp.read()
    infov(opts, 'reading from stdin, type ^D on a new line to exit')
    return bytes(sys.stdin.read(), 'utf-8')


def encrypt(opts: argparse.Namespace, modulus: int, pubexp: int):
    '''
    Encrypt the input using RSA.
    '''
    infov(opts, 'reading the input data')
    plaintext = read_input(opts)
    infov(opts, f'read {len(plaintext)} bytes')
    num_bits = int(math.ceil(math.log(modulus, 2)))
    bytes_per_block =  num_bits // 8  # based on bits
    infov(opts, f'num_bits: {num_bits}')
    infov(opts, f'bytes/block: {bytes_per_block}')
    assert bytes_per_block < 0xffff  # we only allocate 2 bytes for padding

    padding = 0
    while len(plaintext) % bytes_per_block:
        padding += 1
        plaintext += b'x'
    infov(opts, f'padding: {padding}')
    assert (len(plaintext) % bytes_per_block) == 0
    ciphertext = bytes([])
    encrypted = []
    for i in range(0, len(plaintext), bytes_per_block):
        end = i + bytes_per_block
        block = plaintext[i:end]

        # Convert the block to an integer for computation.
        # Arbitrarily chose big endian because consistency is needed and
        # 'big' is fewer letters than 'little'. Also because 'big' is
        # 'network order'.
        block_int = int.from_bytes(block, 'big')

        # Encrypt.
        # Use the fast modular exponentiation algorithm provided by
        # python.
        block_enc_int = int(pow(block_int, pubexp, modulus))

        # Add to the encrypted bytes array.
        # The MSB is always zero.
        block_bytes = block_enc_int.to_bytes(bytes_per_block + 1, byteorder='big')
        ciphertext += block_bytes

    # Setup the prefix.
    version = 0
    prefix = bytes('joes-rsa', 'utf-8')
    prefix += version.to_bytes(2, 'big')
    prefix += padding.to_bytes(2, 'big')

    ciphertext = prefix + ciphertext

    # At this point the data is encrypted.
    # If the user did not specify binary output, output in base64.
    if opts.binary:
        enc = ciphertext
        mode = 'wb'
    else:
        b64 = base64.b64encode(ciphertext)
        data_str = str(b64, 'utf-8').rstrip()
        data_str = '\n'.join(textwrap.wrap(data_str, 64))
        enc = f'''\
-----BEGIN JOES RSA ENCRYPTED DATA-----
{data_str}
-----END JOES RSA ENCRYPTED DATA-----
'''
        mode = 'w'

    # Write out the data.
    if opts.output:
        infov(opts, f'writing to {opts.output}')
        with open(opts.output, mode) as ofp:
            ofp.write(enc)
    else:
        infov(opts, 'writing to stdout')
        sys.stdout.write(enc)


def main():
    '''
    main
    '''
    opts = getopts()
    if opts.seed:
        random.seed(opts.seed)

    modulus, pubexp = read_public_key_file(opts, opts.key)
    infovv(opts, f'modulus: 0x{modulus:x}')
    infovv(opts, f'pubexp : 0x{pubexp:x}')
    encrypt(opts, modulus, pubexp)
    infov(opts, 'done')


if __name__ == '__main__':
    main()
