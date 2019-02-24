import re
import setuptools

with open('README.md', 'r') as ifp:
    long_description = ifp.read()

with open('LICENSE', 'r') as ifp:
    license = ifp.read()

# The __version__ variable in rsa_demo/__init__.py is the
# single source of truth for the version number.
with open('rsa_demo/__init__.py') as ifp:
    match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", ifp.read(), re.M)
    if match:
        version = match.group(1)

setuptools.setup(
    name='rsa_demo',
    version=version,
    author='Joe Linoff',
    author_email='joseph.linoff@gmail.com',
    description='RSA demo package',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license=license,
    url='https://jlinoff.github.com/rsa_demo',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    # Define a bunch of console scripts.
    entry_points={
    'console_scripts': [
        'keygen=rsa_demo.keygen:main',
        'encrypt=rsa_demo.encrypt:main',
        'decrypt=rsa_demo.decrypt:main',
        'gendata=rsa_demo.gendata:main',
        'read_rsa_pkcs1_pem_public=rsa_demo.read_rsa_pkcs1_pem_public:main',
        'read_rsa_pkcs1_private=rsa_demo.read_rsa_pkcs1_private:main',
        'read_rsa_ssh_public=rsa_demo.read_rsa_ssh_public:main',
    ],
},
)
