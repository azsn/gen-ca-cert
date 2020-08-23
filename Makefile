# Edit these to match your OpenSSL installation
# Could also use shared libcrypto instead of static if desired
OPENSSL_INCLUDE=/usr/local/Cellar/openssl@1.1/1.1.1g/include
LIBCRYPTO_STATIC=/usr/local/Cellar/openssl@1.1/1.1.1g/lib/libcrypto.a

CFLAGS+="-I$(OPENSSL_INCLUDE)" "$(LIBCRYPTO_STATIC)"

demo: demo.c gen-ca-cert.c

test: demo
	openssl genrsa -out test_privkey.pem
	
	@echo
	echo "-----BEGIN CERTIFICATE-----" > test_cert.pem
	openssl rsa -in test_privkey.pem -outform DER \
		| ./demo -binout \
		| base64 --break=64 \
		>> test_cert.pem
	echo "-----END CERTIFICATE-----" >> test_cert.pem
	
	@echo
	openssl pkcs12 -export -nodes -cacerts -name "Gen CA Demo" \
		-inkey test_privkey.pem \
		-in test_cert.pem \
		-out test_identity.p12

clean:
	-rm demo
	-rm test_privkey.pem
	-rm test_cert.pem
	-rm test_identity.p12
