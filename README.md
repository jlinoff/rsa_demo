# rsa_demo
Demo that shows how to implement RSA encryption, decryption and key generation.

[![Releases](https://img.shields.io/github/release/jlinoff/rsa_demo.svg?style=flat)](https://github.com/jlinoff/rsa_demo/releases)

This system generates a wheel that contains tools to implement the RSA
algorithm to help people understand how key generation, encryption and
decryption work at a somewhat detailed level.

It provides tools that allow a user to generate public and private key
files using keygen and then uses those files to encrypt and decrypt
files.

The goal is purely pedagogical. Do not try to use it for any
production work. It is too slow and it is not secure (see the
discussion of key generation below). For production work always use
tools like `openssl` and `openssh`.

For the public and private key generation the original PKCS#1 format
is generated which is in ASN.1 DER format. It also generates the SSH
key format (RFC 3447). The generated keys can be read by tools like
openssl and openssh. The key generation only supports version 0. It
does not support multiprimes (version 1).

The RSA encryption and decryption algorithms use a custom format
called `joes-rsa` that I created for this demo. That format consists
of a short prefix with some identifying information that is located
before the encrypted code. You can see the structure in the
`encrypt.py` and `decrypt.py` source code.

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

The source code is available in the `rsa_demo` module directory.

The keys generated are equivalent to running the following command.

```bash
$ ssh-keygen -t rsa -b 2048 -f test1 -N '' -m PEM -q
```

This command is not secure. Do not use it for production keys. One
should always use a non-empty passphrase.

I hope that this helps you understand how RSA works.
