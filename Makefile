TERM_ANSI_BOLD  := "\\033[1m"
TERM_ANSI_GREEN := "\\033[32m"
TERM_ANSI_RESET := "\\033[0m"
PHASE           := printf "${TERM_ANSI_BOLD}=-=-= %s: %s =-=-=${TERM_ANSI_RESET}\n" "`date`"
SUCCESS         := printf "${TERM_ANSI_GREEN}=-=-= %s: %s =-=-=${TERM_ANSI_RESET}\n" "`date`"

.PHONY: default clean pipfile test test/test01 test/test02 wheel

default: test

clean:
	@$(PHASE) $@
	-pipenv clean
	git clean -f -d -x

test: .wheel Pipfile | test/test01 test/test02

# Verify that things work, minimimally using
# ssh generated keys.
test/test01:
	@$(PHASE) "$@"
	@if [ ! -f "$@" ] ; then \
		set -x ; \
		ssh-keygen -t rsa -b 2048 -f $@ -N '' -m PEM -q ; \
		{ set +x; } 2>/dev/null ; \
	fi
	@ls -l $@*
	@$(PHASE) "$@ - read ssh private key: $@"
	pipenv run read_rsa_pkcs1_private $@
	@$(PHASE) "$@ - read ssh public key: $@.pub"
	pipenv run read_rsa_ssh_public $@.pub
	@$(PHASE) "$@ - keygen generate: $@-keygen"
	pipenv run keygen \
		-p $$(pipenv run read_rsa_pkcs1_private $@ | grep prime1 | awk '{printf("0x%s",$$3)}') \
		   $$(pipenv run read_rsa_pkcs1_private $@ | grep prime2 | awk '{printf("0x%s",$$3)}') \
		-e $$(pipenv run read_rsa_pkcs1_private $@ | grep pubexp | awk '{printf("0x%s",$$3)}') \
		-v \
		-o $@-keygen
	@$(PHASE) "$@ - read public private key: $@-keygen"
	pipenv run read_rsa_pkcs1_private $@-keygen
	@$(PHASE) "$@ - read public key: $@-keygen.pub"
	pipenv run read_rsa_ssh_public $@-keygen.pub
	@$(PHASE) "$@ - read public PEM key: $@-keygen.pub.pem"
	pipenv run read_rsa_pkcs1_pem_public $@-keygen.pub.pem
	@$(PHASE) "$@ - diff private keys: $@ $@-keygen"
	diff $@ $@-keygen
	@$(PHASE) "$@ - diff public keys: $@.pub $@-keygen.pub"
	diff $@.pub $@-keygen.pub
	@$(PHASE) "$@ - encrypt: $@.txt"
	pipenv run encrypt -v -k $@.pub -i $@.txt -o $@.txt.enc
	@$(PHASE) "$@ - decrypt: $@.txt.enc"
	pipenv run decrypt -v -k $@ -i $@.txt.enc -o $@.txt.enc.dec
	diff $@.txt $@.txt.enc.dec
	@$(PHASE) "$@ - encrypt binary: $@.txt"
	pipenv run encrypt -v -k $@.pub -i $@.txt -o $@.txt.enc.bin -b
	@$(PHASE) "$@ - decrypt binary: $@.txt.enc.bin"
	pipenv run decrypt -v -k $@ -i $@.txt.enc.bin -o $@.txt.enc.bin.dec
	diff $@.txt $@.txt.enc.dec
	@$(SUCCESS) "$@ - all tests passed"

# Verify that things work, minimimally.
# Use our own keys, verify openssl.
test/test02:
	@$(PHASE) "$@"
	time pipenv run keygen -s 20 -a 0 -o $@ -v
	@$(PHASE) "$@ - read public private key: $@"
	pipenv run read_rsa_pkcs1_private $@
	@$(PHASE) "$@ - read public key: $@.pub"
	pipenv run read_rsa_ssh_public $@.pub
	@$(PHASE) "$@ - read public PEM key: $@.pub.pem"
	pipenv run read_rsa_pkcs1_pem_public $@.pub.pem
	@$(PHASE) "$@ - diff private keys: $@ $@"
	diff $@ $@
	@$(PHASE) "$@ - diff public keys: $@.pub $@.pub"
	diff $@.pub $@.pub
	@$(PHASE) "$@ - encrypt: $@.txt"
	pipenv run encrypt -v -k $@.pub -i $@.txt -o $@.txt.enc
	@$(PHASE) "$@ - decrypt: $@.txt.enc"
	pipenv run decrypt -v -k $@ -i $@.txt.enc -o $@.txt.enc.dec
	diff $@.txt $@.txt.enc.dec
	@$(PHASE) "$@ - encrypt binary: $@.txt"
	pipenv run encrypt -v -k $@.pub -i $@.txt -o $@.txt.enc.bin -b
	@$(PHASE) "$@ - decrypt binary: $@.txt.enc.bin"
	pipenv run decrypt -v -k $@ -i $@.txt.enc.bin -o $@.txt.enc.bin.dec
	diff $@.txt $@.txt.enc.dec
	@$(SUCCESS) "$@ - all tests passed"

# Force the wheel to be built.
wheel:
	-rm -f .wheel
	$(MAKE) .wheel

# Not sure why pyasn1 does not install properly
# from pipenv.
.wheel:
	@$(PHASE) "wheel"
	-rm -rf build rsa_demo-* dist
	pipenv run python setup.py sdist bdist_wheel
	-pipenv run pip uninstall --yes rsa_demo
	pipenv run pip install pyasn1 faker
	pipenv run pip install dist/*whl
	pipenv run keygen -h
	pipenv run encrypt -h
	pipenv run decrypt -h
	@touch $@

# This was done manually because it is a slow operation, this exists
# to show how it was run.
Pipfile:
	@$(PHASE) $@
	pipenv --python 3.7
	pipenv install pip faker setuptools pylint pycodestyle pyasn1 random faker
	pipenv check
