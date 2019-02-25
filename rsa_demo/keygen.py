'''
This tool creates a 4096 RSA public/private key pair in ASN.1 DER
format (same as ssh-keygen).

It is not smart and does not provide a lot of options because the goal
is pedagogical. For example, all output is in the old RSA specific
PKCS#1 format. It would be trivial to add additional formats like
PKCS#7, PKCS#8 or PKCS#11 but that can be left as an exercise for the
reader. It also does not support multi-prime RSA (version 1). Finally
it does not support certificate generation.

The first thing the program does is generate two very large (2048 bit
by default) prime number. It then creates a large, hard to factor
composite number (modulus) of both of them. The user has the option of
providing the prime numbers directly so that the calculations can be
verified.

The Miller-Rabin probabilistic primality test is used during the prime
number generation to test prime number candidates. The program has
multiple implementations of this test from different sources and it
allows you to choose which one to use. It also has the option of
running them all to make sure that they provide the same results.

It then uses the modulus and the prime numbers to calculate the
totient, the exponents for encrypting (public) and decrypting
(private) a block and the CRT (Chinese Remainder Theorem) coefficient.
This work is done, in part, using the extended Euclids Algorithm
(extended to generate the Bezout coefficients).

After that it writes out three files the private key file (PKCS#1),
the public key PEM file (PKCS#1) and ssh formatted public key file.

The user can also specify the choice for the public encryption
exponent whichcan be used with explicit primes to duplicate the
results of the ssh-keygen program.

Here is one way to generate an old style RSA key pair (BEGIN RSA
PRIVATE KEY). The data is stored in ASN.1 DER binary format is
base64 encoded.

   $ ssh-keygen -t rsa -b 2048 -f test1 -N '' -m PEM -q
   $ head -1 test1
   -----BEGIN RSA PRIVATE KEY-----
   $ openssl asn1parse -in test1 | tr '\t' ' ' | cat -n | cut -c -80
        1    0:d=0  hl=4 l=1187 cons: SEQUENCE
        2    4:d=1  hl=2 l=   1 prim: INTEGER  :00
        3    7:d=1  hl=4 l= 257 prim: INTEGER  :A5B0F2905F0D5D4E27F9093DE
        4  268:d=1  hl=2 l=   3 prim: INTEGER  :010001
        5  273:d=1  hl=4 l= 256 prim: INTEGER  :63569F572765DFD707E82B3E4
        6  533:d=1  hl=3 l= 129 prim: INTEGER  :D6A4C2ED576CAD34B047ABD67
        7  665:d=1  hl=3 l= 129 prim: INTEGER  :C59D9F3DD7BEB123F1B5012FE
        8  797:d=1  hl=3 l= 128 prim: INTEGER  :62696876297F4A6ABDE81E815
        9  928:d=1  hl=3 l= 129 prim: INTEGER  :B52B8B9953D8D467E2A991FC1
       10 1060:d=1  hl=3 l= 128 prim: INTEGER  :3F5F966626D9483D71D6F8205

The ASN.1 DER fields can be seen by running this command:

   $ openssl rsa -in test1 -noout -text
   .
   .

Here they are cross-referenced with the asn1parse output above:

    #  Name              Partial Value
   ==  ================  ==========================
    2  version           :00
    3  modulus           :A5B0F2905F0D5D4E27F9093DE...
    4  publicExponent    :010001
    5  privateExponent   :63569F572765DFD707E82B3E4...
    6  prime1            :D6A4C2ED576CAD34B047ABD67...
    7  prime2            :C59D9F3DD7BEB123F1B5012FE...
    8  exponent1         :62696876297F4A6ABDE81E815...
    9  exponent2         :B52B8B9953D8D467E2A991FC1...
   10  coefficient       :3F5F966626D9483D71D6F8205...

To re-create that output with this program, run it as follows:

   $ ./keygen.py -p 0xD6A4C2ED576CAD34B047ABD67... 0xC59D9F3DD7BEB123F1B5012FE... \\
                 -e 0x010001 \\
                 -v \\
                 -o test1a
      1 SEQUENCE
      2 version         : 0
      3 modulus         : 2048 a5b0f2905f0d5d4e27f9093de6a73a251fc8a26751c7b1bb2c05
      4 public_exponent : 17 10001
      5 private_exponent: 2047 63569f572765dfd707e82b3e4d975d28fcd1516d187edd741684
      6 prime1          : 1024 d6a4c2ed576cad34b047abd671f6c3e9290297e28401e7c1c3dc
      7 prime2          : 1024 c59d9f3dd7beb123f1b5012fed0a7f752671469c9a96d3910a51
      8 exponent1       : 1023 62696876297f4a6abde81e8153ff3013d719b949c1fc9da5d987
      9 exponent2       : 1024 b52b8b9953d8d467e2a991fc113245a5ee677d580775ed629476
     10 crt_coefficient : 1022 3f5f966626d9483d71d6f8205a89d97631765ae45a249171fe7a
     11 *totient        : 2048 a5b0f2905f0d5d4e27f9093de6a73a251fc8a26751c7b1bb2c05

Note that the full prime numbers and exponents must be used.

As you can see, the results match. The results can be verified using
diff as follows:

   $ diff test1 test1a
   $ diff test1.pub test1a.pub

'''
import argparse
import base64
import getpass
import math
import os
import random
import socket
import sys
import textwrap
from typing import Tuple

from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder

# Is the sys.path.append really needed?
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from rsa_demo import __version__
from rsa_demo.utils import err, infov, infovv
from rsa_demo.eea import is_prime0, is_prime1, is_prime2, is_prime3


# pylint: disable=too-few-public-methods,too-many-instance-attributes
class RSAFactors:
    '''
    Contains all of the RSA factors.
    '''
    def __init__(self, prime1: int, prime2: int, public_exponent: int=0):
        self.m_version = 0  # not multiprime
        self.m_prime1 = max(prime1, prime2)
        self.m_prime2 = min(prime1, prime2)
        assert math.gcd(prime1, prime2) == 1

        self.m_modulus = self.m_prime1 * self.m_prime2
        self.m_totient = (self.m_prime1 - 1) * (self.m_prime2 - 1)

        # Set the public exponent.
        if public_exponent < 3:
            self.m_public_exponent = random.randint(3, self.m_totient - 1)
            while math.gcd(self.m_public_exponent, self.m_totient) != 1:
                self.m_public_exponent = random.randint(3, self.m_totient - 1)
        else:
            self.m_public_exponent = public_exponent
        assert math.gcd(self.m_public_exponent, self.m_totient) == 1

        # Set the private exponent and CRT coefficient.
        self._gen_private_exponent()
        self._gen_crt_coefficient()

        # Set the calculation exponents.
        # https://tools.ietf.org/html/rfc3447
        self.m_exponent1 = self.m_private_exponent % (self.m_prime1 - 1)
        self.m_exponent2 = self.m_private_exponent % (self.m_prime2 - 1)

    def _gen_private_exponent(self):
        '''
        Calculate the private exponent using the extended Euclidean algorithm.
        '''
        b, _, y0 = xgcd(self.m_totient, self.m_public_exponent)
        while y0 < 0:
            y0 += self.m_totient
        self.m_private_exponent = y0 % self.m_totient
        assert b == 1

    def _gen_crt_coefficient(self):
        '''
        Generate the chinese remainder theorem coefficient.
        '''
        # I think y0 is the valid choice because
        #   prime1 >= prime2
        b, _, y0 = xgcd(self.m_prime1, self.m_prime2)
        while y0 < 0:
            y0 += self.m_prime1
        self.m_crt_coefficient = y0 % self.m_prime1  # modular inverse
        assert b == 1


def xgcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    return (g, x, y) such that a*x + b*y = g = gcd(a, b)
    Citation: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm#Python
    """
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def generate_prime_candidate(nbits: int) -> int:
    '''
    Generate a candidate prime number composed of n-bits.
    Set the MSB and LSB to 1.
    '''
    candidate = random.getrandbits(nbits)
    candidate |= (1 << (nbits - 1)) | 1
    return candidate


def generate_prime(opts: argparse.Namespace) -> int:
    '''
    Generate a random prime number composed of n-bits.
    '''
    prime_functions = [
        is_prime0,
        is_prime1,
        is_prime2,
        is_prime3
    ]
    algorithm = prime_functions[opts.algorithm] if opts.algorithm >= 0 else None
    nbits = opts.numbits // 2
    count = 1
    candidate = generate_prime_candidate(nbits)
    while True:
        if algorithm:
            if algorithm(candidate, opts.miller_rabin_accuracy):
                if opts.verbose:
                    sys.stdout.write(f'[{opts.algorithm}:{count}]')
                    sys.stdout.flush()
                    sys.stdout.write('\n')
                return candidate
        else:
            # If the algorithm is negative, do all of them.
            matched = False
            for i, func in enumerate(prime_functions):
                if func(candidate, opts.miller_rabin_accuracy):
                    if opts.verbose:
                        sys.stdout.write(f'[{i}:{count}]')
                        sys.stdout.flush()
                    matched = True
            if matched:
                if opts.verbose:
                    sys.stdout.write('\n')
                return candidate

        if opts.verbose and (count % opts.num_primality_tests_per_dot) == 0:
            sys.stdout.write('.')
            sys.stdout.flush()

        if opts.random_retries:
            candidate = generate_prime_candidate(nbits)
        else:
            # Estimates of prime distance:
            # https://arxiv.org/pdf/1002.0442.pdf
            candidate += 2

        count += 1


def getopts() -> argparse.Namespace:
    '''
    Get the command line options.
    '''
    def gettext(string: str) -> str:
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

    # Example 2: generate a 4096 RSA modulus to mykeys and mykeys.pub
    #            using the default algorithm.
    $ {base} -o mykeys -v
    $ openssl asn1parse -in mykeys | cat -n

    # Example 3: generate a 4096 RSA modulus to mykeys and mykeys.pub.
    #            using all algorithms (slower).
    $ {base} -o mykeys -a -1 -v

    # Example 4: test the performance of each algorithm, set the seed to
    #            make sure that all random operations have the same results
    $ time {base} -a 0 -s 1
    $ time {base} -a 1 -s 1
    $ time {base} -a 2 -s 1
    $ time {base} -a 3 -s 1
'''

    afc = argparse.RawTextHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=afc,
                                     description=desc[:-2],
                                     usage=usage,
                                     epilog=epilog + ' \n')

    parser.add_argument('-a', '--algorithm',
                        action='store',
                        type=int,
                        default=0,
                        metavar=('NUM'),
                        help='''\
The algorithm to use for the primality test.
There are four: 0, 1, 2 or 3.
This is for internal use only, all four
algorithms should generate the same results.
If you want to test all four algorithms simultaneously,
enter -1 as the algorithm id.
Default: %(default)s.

''')

    parser.add_argument('-e', '--encrypt-exponent',
                        action='store',
                        type=str,
                        default='65537',
                        metavar=('NUM'),
                        help='''\
The public encryption exponent.
Default: %(default)s.

''')

    parser.add_argument('-m', '--miller-rabin-accuracy',
                        action='store',
                        type=int,
                        default=256,
                        metavar=('NUM'),
                        help='''\
The accuracy (number of trials) used in the Miller-Rabin
primality test.
Default: %(default)s.

''')

    parser.add_argument('-n', '--numbits',
                        action='store',
                        type=int,
                        default=4096,
                        metavar=('NUM'),
                        help='''\
The number of bits in the composite (modulus) number.
It must be a power of two.
Standard values are 4096, 2048 and 1024.
Default: %(default)s.

''')

    parser.add_argument('-o', '--out',
                        action='store',
                        metavar=('FILE'),
                        help='''\
Private key file name.
Default: %(default)s.

''')

    parser.add_argument('-p', '--primes',
                        action='store',
                        nargs=2,
                        type=str,
                        metavar=('INT', 'INT'),
                        help='''\
Allow the user to specify their own prime numbers.
This can be used with the -e (public encryption
exponent) option to duplicate the keys files
generated by SSH.

Hex values must have a '0x' prefix.

''')

    parser.add_argument('-r', '--random-retries',
                        action='store_true',
                        help='''\
Normally, when the primality test fails, the
next candidate is obtained by adding 2. This
option modifies the system to use random
numbers for the retry.

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

    parser.add_argument('-z', '--num-primality-tests-per-dot',
                        action='store',
                        type=int,
                        default=10,
                        metavar=('NUM'),
                        help='''\
The number of primality tests per dot in verbose
mode.
Default: %(default)s.
''')

    opts = parser.parse_args()
    if opts.numbits not in [1024, 2048, 4096]:
        err(f'invalid value for -n {numbits}: expected 1024, 2048, 4096')
    return opts


def write_rsa_pkcs1_private(opts: argparse.Namespace, rsa: RSAFactors) -> None:
    '''
    Write the PKCS#1 private key.
    Citation: https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
    Citation: http://blog.oddbit.com/2011/05/08/converting-openssh-public-keys/
    Citation: https://tools.ietf.org/html/rfc3447
    Note that this wraps at 64 to match SSH.
    '''
    pkcs1_seq = univ.Sequence()
    pkcs1_seq.setComponentByPosition(0, univ.Integer(rsa.m_version))  # Version (0-std, 1-multiprime)
    pkcs1_seq.setComponentByPosition(1, univ.Integer(rsa.m_modulus))  # modulus
    pkcs1_seq.setComponentByPosition(2, univ.Integer(rsa.m_public_exponent))  # publicExponent
    pkcs1_seq.setComponentByPosition(3, univ.Integer(rsa.m_private_exponent))  # privateExponent
    pkcs1_seq.setComponentByPosition(4, univ.Integer(rsa.m_prime1))  # prime1
    pkcs1_seq.setComponentByPosition(5, univ.Integer(rsa.m_prime2))  # prime2
    pkcs1_seq.setComponentByPosition(6, univ.Integer(rsa.m_exponent1))  # exponent1
    pkcs1_seq.setComponentByPosition(7, univ.Integer(rsa.m_exponent2))  # exponent2
    pkcs1_seq.setComponentByPosition(8, univ.Integer(rsa.m_crt_coefficient))  # coefficient
    data = base64.b64encode(der_encoder.encode(pkcs1_seq))
    data_str = str(data, 'utf-8').rstrip()
    data_str = '\n'.join(textwrap.wrap(data_str, 64))
    path = opts.out
    infov(opts, f'writing {path} - PCKS#1 private')
    with open(path, 'w') as ofp:
        ofp.write(f'''\
-----BEGIN RSA PRIVATE KEY-----
{data_str}
-----END RSA PRIVATE KEY-----
''')


def write_rsa_pkcs1_pem_public(opts: argparse.Namespace, rsa: RSAFactors) -> None:
    '''
    Write PEM RSA public key: PKCS#1.
    Citation: http://blog.oddbit.com/2011/05/08/converting-openssh-public-keys/
    Note that this wraps at 64 to match SSH.
    '''
    pkcs1_seq = univ.Sequence()
    pkcs1_seq.setComponentByPosition(0, univ.Integer(rsa.m_modulus))
    pkcs1_seq.setComponentByPosition(1, univ.Integer(rsa.m_public_exponent))
    data = base64.b64encode(der_encoder.encode(pkcs1_seq))
    data_str = str(data, 'utf-8').rstrip()
    data_str = '\n'.join(textwrap.wrap(data_str, 64))
    path = opts.out + '.pub.pem'
    infov(opts, f'writing {path} - PCKS#1 public')
    with open(path, 'w') as ofp:
        ofp.write(f'''\
-----BEGIN RSA PUBLIC KEY-----
{data_str}
-----END RSA PUBLIC KEY-----
''')


def write_rsa_ssh_public(opts: argparse.Namespace, rsa: RSAFactors) -> None:
    '''
    Write SSH format: https://tools.ietf.org/html/rfc4716.
    Citation: http://blog.oddbit.com/2011/05/08/converting-openssh-public-keys/
    Citation: http://blog.thedigitalcatonline.com/blog/2018/04/25/rsa-keys/

    The base64 fields are composed of 3 length/data pairs with all
    data in big endian format.
       1. Prefix (the algorithm):
             length is 7
             data is "ssh-rsa"
       2. Public (encryption) key:
             length is the number of bytes in the public key
             data is the key
       3. Modulus:
             length is the number of bytes + 1 (to guarantee unsigned)
             data is the modulus
    '''
    # Prefix.
    pre_bytes = bytes('ssh-rsa', 'utf-8')
    pre_size = len(pre_bytes).to_bytes(4, byteorder='big')

    # Public key.
    pub_num_bytes = math.ceil(math.log(rsa.m_public_exponent, 256))
    pub_bytes = rsa.m_public_exponent.to_bytes(pub_num_bytes, byteorder='big')
    pub_size = pub_num_bytes.to_bytes(4, byteorder='big')

    # Modulus.
    mod_num_bytes = 1 + math.ceil(math.log(rsa.m_modulus, 256))
    mod_bytes = rsa.m_modulus.to_bytes(mod_num_bytes, byteorder='big')
    mod_size = mod_num_bytes.to_bytes(4, byteorder='big')

    # Byte data.
    byte_array = pre_size + pre_bytes + pub_size + pub_bytes + mod_size + mod_bytes
    data = base64.b64encode(byte_array)
    data_str = str(data, 'utf-8').rstrip()

    # Write to file.
    path = opts.out + '.pub'
    infov(opts, f'writing {path} - SSH public')
    with open(path, 'w') as ofp:
        ofp.write(f'''\
ssh-rsa {data_str} {getpass.getuser()}@{socket.gethostname()}
''')


def write_keys(opts: argparse.Namespace, rsa: RSAFactors) -> None:
    '''
    Write out the key data.
    '''
    if opts.verbose:
        print(f'''
RSA Parameters

   1 SEQUENCE
   2 version         : {rsa.m_version}
   3 modulus         : {rsa.m_modulus.bit_length()} {rsa.m_modulus:x}
   4 public_exponent : {rsa.m_public_exponent.bit_length()} {rsa.m_public_exponent:x}
   5 private_exponent: {rsa.m_private_exponent.bit_length()} {rsa.m_private_exponent:x}
   6 prime1          : {rsa.m_prime1.bit_length()} {rsa.m_prime1:x}
   7 prime2          : {rsa.m_prime2.bit_length()} {rsa.m_prime2:x}
   8 exponent1       : {rsa.m_exponent1.bit_length()} {rsa.m_exponent1:x}
   9 exponent2       : {rsa.m_exponent2.bit_length()} {rsa.m_exponent2:x}
  10 crt_coefficient : {rsa.m_crt_coefficient.bit_length()} {rsa.m_crt_coefficient:x}
  11 *totient        : {rsa.m_totient.bit_length()} {rsa.m_totient:x}
''')
    if opts.out:
        # Write key files.
        write_rsa_pkcs1_private(opts, rsa)
        write_rsa_pkcs1_pem_public(opts, rsa)
        write_rsa_ssh_public(opts, rsa)


def get_int_arg(arg) -> int:
    '''
    Allow hex and decimal integer specifications.

    The user must specify a 0x prefix (or something
    similar to designate hex).
    '''
    base = 10
    base_prefixes = {
        'x': 16,
        'X': 16,
        '0x': 16,
        '0X': 16,
        }
    for key, val in base_prefixes.items():
        if arg.startswith(key):
            base = val
            break
    value = int(arg, base)
    return value


def main() -> None:
    '''
    Main entry point.
    '''
    opts = getopts()
    if opts.seed:
        random.seed(opts.seed)
    public_exponent = get_int_arg(opts.encrypt_exponent)
    if opts.primes:
        prime1 = get_int_arg(opts.primes[0])
        prime2 = get_int_arg(opts.primes[1])
    else:
        prime1 = generate_prime(opts)
        prime2 = generate_prime(opts)
    assert prime1 != prime2
    rsa = RSAFactors(prime1, prime2, public_exponent)
    write_keys(opts, rsa)
    infov(opts, 'done')


if __name__ == '__main__':
    main()
