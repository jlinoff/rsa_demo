'''
Extended Euclidean algorithms for testing.
'''
import random
from typing import Tuple


def decompose(n: int) -> Tuple[int, int]:
    '''
    Citation: https://jeremykun.com/2013/06/16/miller-rabin-primality-test/
    Citation: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    '''
    exponentOfTwo = 0

    while n % 2 == 0:
        n = n // 2
        exponentOfTwo += 1

    return exponentOfTwo, n


def isWitness(possibleWitness: int, p: int, exponent: int, remainder: int) -> bool:
    '''
    Citation: https://jeremykun.com/2013/06/16/miller-rabin-primality-test/
    Citation: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    '''
    possibleWitness = pow(possibleWitness, remainder, p)

    if possibleWitness == 1 or possibleWitness == p - 1:
        return False

    for _ in range(exponent):
        possibleWitness = pow(possibleWitness, 2, p)

        if possibleWitness == p - 1:
            return False

    return True


def is_prime0(p: int, accuracy: int=100) -> bool:
    '''
    Citation: https://jeremykun.com/2013/06/16/miller-rabin-primality-test/
    Citation: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

    Miller-Rabin primality test.
    '''
    if p == 2 or p == 3: return True
    if p < 2: return False

    exponent, remainder = decompose(p - 1)

    for _ in range(accuracy):
        possibleWitness = random.randint(2, p - 2)
        if isWitness(possibleWitness, p, exponent, remainder):
            return False

    return True


def is_prime1(n: int, t: int=8) -> bool:
    """
    Citation: https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#Python
    Citation: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

    Miller-Rabin primality test.

    A return value of False means n is certainly not prime. A return value of
    True means n is very likely a prime.
    """
    #Miller-Rabin test for prime
    if n==0 or n==1 or n==4 or n==6 or n==8 or n==9:
        return False

    if n==2 or n==3 or n==5 or n==7:
        return True

    s = 0
    d = n-1
    while d%2==0:
        d>>=1
        s+=1
    assert(2**s * d == n-1)

    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True

    for _ in range(t):  # number of trials
        a = random.randrange(2, n)
        if trial_composite(a):
            return False

    return True


def is_prime2(candidate: int, num_tests:int =128) -> bool:
    '''
    Citation: https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb
    Citation: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

    Miller-Rabin primality test.

    Test if a number is prime

    Args:
       candidate - the number to test
       num_tests - the number of tests to do

        return True if candidate is prime
    '''
    # Simple tests for small numbers.
    if candidate in [2, 3, 5, 7]:
        return True
    if candidate <= 1 or candidate % 2 == 0:
        return False

    # Decompose to find the remainder and exponent.
    exponent = 0
    remainder = candidate - 1
    while remainder & 1 == 0:
        exponent += 1
        remainder //= 2
    assert(2 ** exponent * remainder == candidate - 1)

    # Check witnesses.
    for _ in range(num_tests):
        accuracy = random.randrange(2, candidate - 1)
        possible_witness = pow(accuracy, remainder, candidate)
        if possible_witness not in (1, candidate - 1):
            j = 1
            while j < exponent and possible_witness != candidate - 1:
                possible_witness = pow(possible_witness, 2, candidate)
                if possible_witness == 1:
                    return False
                j += 1
            if possible_witness != candidate - 1:
                return False

    return True


def is_prime3(candidate: int, num_tests: int=128) -> bool:
    '''
    Citation: https://inventwithpython.com/rabinMiller.py
    Citation: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

    Miller-Rabin primality test.

    Returns True if candidate is a prime number.
    '''
    remainder = candidate - 1
    exponent = 0
    while remainder % 2 == 0:
        # keep halving remainder while it is even (and use exponent
        # to count how many times we halve remainder)
        remainder = remainder // 2
        exponent += 1

    # try to falsify candidate's primality num_tests times
    for _ in range(num_tests):
        accuracy = random.randrange(2, candidate - 1)
        possible_witness = pow(accuracy, remainder, candidate)
        if possible_witness != 1:
            # this test does not apply if possible_witness is 1.
            i = 0
            while possible_witness != (candidate - 1):
                if i == exponent - 1:
                    return False
                i = i + 1
                possible_witness = (possible_witness ** 2) % candidate
    return True


def generate_prime_candidate(nbits: int) -> int:
    '''
    Generate a candidate prime number composed of n-bits.
    Set the MSB and LSB to 1.
    '''
    candidate = random.getrandbits(nbits)
    candidate |= (1 << (nbits - 1)) | 1
    return candidate
