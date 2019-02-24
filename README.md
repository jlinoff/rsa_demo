# rsa_demo
Demo that shows how to implement RSA encryption, decryption and key generation.

[![Releases](https://img.shields.io/github/release/jlinoff/rsa_demo.svg?style=flat)](https://github.com/jlinoff/rsa_demo/releases)

This system generates a wheel that contains tools to implement the RSA
algorithm to help people understand how key generation, encryption and
decryption work at a somewhat detailed level.

It provides tools that allow a user to generate public and private key
files using keygen and then uses those files to encrypt and decrypt
files.

### Important Disclaimer
The goal is purely pedagogical. Do not try to use it for any
production work. It is too slow and it is not secure (see the
discussion of key generation below). For production work always use
tools like `openssl` and `openssh`.

### Key Generation
For the public and private key generation the original PKCS#1 format
is generated which is in ASN.1 DER format. It also generates the SSH
key format (RFC 3447). The generated keys can be read by tools like
openssl and openssh. The key generation only supports version 0. It
does not support multiprimes (version 1).

### RSA Implementation
The RSA encryption and decryption algorithms use a custom format
called `joes-rsa` that I created for this demo. That format consists
of a short prefix with some identifying information that is located
before the encrypted code. You can see the structure in the
`encrypt.py` and `decrypt.py` source code.

### A Simple Example
Here is a simple example of how to use it:

```bash
   $ # Download
   $ git clone https://github.com/jlinoff/rsa_demo.git
   $ cd rsa_demo

   $ # Install the system in a local pipenv.
   $ make

   $ # Create a dummy data file.
   $ pipenv run gendata >dummy.txt

   $ # Create public and private keys.
   $ # This can take a few minutes.
   $ # Using -s 20 speeds it up a bit.
   $ pipenv run keygen -o dummykeys -s 20 -v

   $ # Encrypt the dummy.
   $ pipenv run encrypt -k dummykeys.pub -i dummy.txt -o dummy.txt.enc -v

   $ # Decrypt the encrypted data.
   $ pipenv run decrypt -k dummykeys -i dummy.txt.enc -o dummy.txt.dec -v

   $ # Verify that the decrypted file matches the original file.
   $ diff dummy.txt dummy.txt.dec

   $ # Dump the key files using the openssl tool (it is PKCS#1 compatible).
   $ openssl asn1parse -in dummykeys | tr '\t' ' ' | cat -n | cut -c -80
   .
   .
   $ openssl asn1parse -in dummykeys.pub | tr '\t' ' ' | cat -n | cut -c -80
   .
   .
```

### A More Complex Example
In this example Alice and Bob want to communicate a message that cannot be
decoded by someone observing their communication.

The important idea is that the public key is used to encrypt a message and the
private key is used to decrypt that same message.

1. Alice creates the key files: `alice` (private) and `alice.pub` (public).
2. Alice then stores the private key in a safe place and sends the public key to Bob. It doesn't matter if anyone intercepts the public key because they can only use it to encrypt messages for Alice.
3. Bob creates the key files: `bob` (private) and `bob.pub` (public).
4. Bob then stores the private key in a safe place and sends the public key to Bob. It doesn't matter if anyone intercepts the public key because they can only use it to encrypt messages for Bob.
5. At this point Alice has three files: `alice`, `alice.pub` and `bob.pub`. Bob also has three files: `bob`, `bob.pub` and `alice.pub` Alice will use `bob.pub` to encrypt messages that are sent to Bob and Bob will use `alice.pub` to encrypt messages that are sent to Alice.
6. Alice composes her plaintext message in `message-to-bob.txt`, encrypts it using `bob.pub` as the public key file and sends it to Bob.
7. Bob receives the encrypted message and then decrypts it using the `bob` private key file. If anyone intercepts the encrypted message, they cannot decrypt because they do _not_ have the `bob` private key file.
8. Bob then composes a response to Alice in `message-to-alice.txt`, encrypts it using `alice.pub` and sends it to Alice.
9. Alice receives the encrypted message and then decrypts it using the `alice` private key file. If anyone intercepts the encrypted message, they cannot decrypt because they do _not_ have the `alice` private key file.

At this point Alice and Bob have communicated back forth. The messages are secure from observers that can only observe their communications. Unfortunately this does not mean that the messages are secure.

### Vulnerabilities
Here are some of the tactics an attacker could employ to access their communications.

1. System hack: an attacker could access their computer systems and take their private key files. That would allow the attacker to decrypt all messages.
2. MITM (man-in-the-middle) attach: An attacker could sit in the middle of the communications between Alice and Bob and spoof them. That means that when Alice talks to Bob, the attacker intercepts the communications from Alice and substitutes their (the attackers) public key in the message to Bob. When Bob responds he is using the attackers public key file to encrypt messages for Alice. When he sends the encrypted message back to Alice, the attacker intercepts it, decodes the message using their (the attackers private key), re-encrypts using Alice's original public key and then sends it to Alice. Thus, Alice and Bob see the same communication pattern as before _but their communications have been compromised_. And vice-versa for the reverse direction.
3. Library/Tool compromise - An attacker could provide Alice and Bob with a hacked version of openssl or openssh or a hacked system library (like a pseudo-random-number (PNG) library). Whenever Alice or Bob create their keys using the compromised tools, the attacker will be able to decrypt the messages.
4. Algorithm compromise - An attacker figures out a vulnerability in one or more of the underlying algorithms. This is the main reason that you should never use tools and libraries (like the ones in this demo) for secure communications. You want battle tested tools that are under constant scrutiny by experts to detect and fix vulnerabilities.

### Mitigation
Here are some of the mitigation tactics.

1. The probability of system hacks can be reduced by good security hygiene.
2. The probability of MITM attacks can be reduced by using certificates.
3. The probability of library/tool compromise attacks can be reduced by verifying the official checksums of all libraries and tools used (white-listing). This is part of good security hygiene but deserves to be called out because it is often neglected.
4. The probabiliy of an algorithm compromise is reduced by continuing to encourage security research.

### Errata
The source code is available in the `rsa_demo` module directory.

The keys generated are equivalent to running the following command.

```bash
$ ssh-keygen -t rsa -b 2048 -f test1 -N '' -m PEM -q
```

This command is not secure. Do not use it for production keys. One
should always use a non-empty passphrase.

I hope that this helps you understand how RSA works.
