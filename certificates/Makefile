## Variables:
PASSWORD=changeit
DOMAIN=openbanking4.dev

FOLDER_GLOBAL=global
FOLDER_SERVER_CERT=server
FOLDER_CLIENTS_CERT=clients

## Default key parameters
KEY_ALGO=RSA
KEY_SIZE=2048
KEY_SIGNING_ALGO=SHA256withRSA

VALIDITY=825

## CN = Common Name
## OU = Organization Unit
## O  = Organization Name
## L  = Locality Name
## ST = State Name
## C  = Country (2-letter Country Code)
## E  = Email
## For server certificates, the Common Name (CN) must be the hostname

CERT_OU=Spring-security-multi-auth-example
CERT_O=OpenBanking4.dev
CERT_L=Bristol
CERT_ST=Avon
CERT_C=GB

## CA
CA_ALIAS=Spring-security-multi-auth-example-ca
CA_CRT=$(FOLDER_GLOBAL)/ca.crt
CA_P12=$(FOLDER_GLOBAL)/ca.p12
CA_KEYSTORE=$(FOLDER_GLOBAL)/ca-keystore.jks
CA_DNAME='CN=$(CA_ALIAS)),OU=$(CERT_OU),O=$(CERT_O),L=$(CERT_L),ST=$(CERT_ST),C=$(CERT_C)'

## HOSTNAME
HOSTNAME_SERVER=server.${DOMAIN}
ALIAS_CLIENT_ALICE=alice
ALIAS_CLIENT_BOB=bob

## DNAME
DNAME_SERVER='CN=$(HOSTNAME_SERVER),OU=$(CERT_OU),O=$(CERT_O),L=$(CERT_L),ST=$(CERT_ST),C=$(CERT_C)'
DNAME_CLIENT_ALICE='CN=$(ALIAS_CLIENT_ALICE),OU=$(CERT_OU),O=$(CERT_O),L=$(CERT_L),ST=$(CERT_ST),C=$(CERT_C)'
DNAME_CLIENT_BOB='CN=$(ALIAS_CLIENT_BOB),OU=$(CERT_OU),O=$(CERT_O),L=$(CERT_L),ST=$(CERT_ST),C=$(CERT_C)'

## Keystore
KEYSTORE_SERVER="${FOLDER_SERVER_CERT}/keystore.jks"
KEYSTORE_CLIENTS="${FOLDER_CLIENTS_CERT}/keystore.jks"

## Truststore

TRUSTSTORE=${FOLDER_GLOBAL}/truststore.jks
## Makefile commands:

all: clean \
 create-CA \
 create-truststore \
 create-clients-cert \
 create-server-cert \
 deploy


create-server-cert: init-folder-server-cert \
        create-server-keystore \
        create-server-key

create-clients-cert: init-folder-clients-cert \
        create-clients-keystore \
        create-clients-key

init-folder-ca-cert:
	## Generate ca cert folder
	mkdir ${FOLDER_GLOBAL}

init-folder-server-cert:
	## Generate server cert folder
	mkdir ${FOLDER_SERVER_CERT}

init-folder-clients-cert:
	## Generate clients cert folder
	mkdir ${FOLDER_CLIENTS_CERT}

## Create CA
define create_certificate-authority
	$(eval CA_ALIAS=$(1))
	$(eval CA_CRT=$(2))
	$(eval CA_P12=$(3))
	$(eval CA_KEYSTORE=$(4))
	$(eval CA_DNAME=$(5))

	@echo "Generate $(CA_ALIAS) CA"
	keytool -genkey -alias $(CA_ALIAS) -ext BC=ca:true \
		-keyalg $(KEY_ALGO) -keysize $(KEY_SIZE) -sigalg $(KEY_SIGNING_ALGO) \
		-keypass $(PASSWORD) \
		-validity $(VALIDITY) -dname $(CA_DNAME) \
		-keystore $(CA_KEYSTORE) -storepass $(PASSWORD)

	@echo "Export CA public key"
	keytool -export -alias $(CA_ALIAS) -file $(CA_CRT) -rfc \
		-keystore $(CA_KEYSTORE) -storepass $(PASSWORD)

	@echo "Export CA private key"
	keytool -importkeystore -srcalias $(CA_ALIAS) \
		-srckeystore $(CA_KEYSTORE) -srcstorepass $(PASSWORD) \
		-destkeystore $(CA_P12) -deststorepass $(PASSWORD) \
		-deststoretype PKCS12
endef

create-CA: init-folder-ca-cert \
	# Create CA
	$(call create_certificate-authority,$(CA_ALIAS), $(CA_CRT), $(CA_P12), \
	$(CA_KEYSTORE), $(CA_DNAME))

## Create Truststores
create-truststore:
	# Import CA
	keytool -import -trustcacerts -noprompt -alias $(CA_ALIAS) -file $(CA_CRT) -keystore $(TRUSTSTORE) \
	-storepass $(PASSWORD)



## Create keystores
create-server-keystore:
	## Import CA into keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_SERVER) \
	-srckeystore $(CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)

create-clients-keystore:
	## Import CA into keystore
	keytool -importkeystore \
	-deststorepass $(PASSWORD) -destkeystore $(KEYSTORE_CLIENTS) \
	-srckeystore $(CA_P12) -srcstoretype PKCS12 -srcstorepass $(PASSWORD)

define generate_key
	$(eval ALIAS=$(1))
	$(eval DNAME=$(2))
	$(eval SAN=$(3))
	$(eval KEYSTORE=$(4))
	$(eval PASSWORD=$(5))
	$(eval FOLDER=$(6))
	$(eval BROWSER_CERT=b-$(ALIAS).p12)

	@echo "Generate $(ALIAS) certificate"
	keytool -genkey -alias $(subst wildcard,*,$(ALIAS)) \
		-keyalg $(KEY_ALGO) -keysize $(KEY_SIZE) -sigalg $(KEY_SIGNING_ALGO) \
		-keypass $(PASSWORD) \
		-validity $(VALIDITY) -dname $(subst wildcard,*,$(DNAME)) \
		-ext SAN=$(SAN) \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Export $(ALIAS) private certificate for importing into a browser"
	keytool -importkeystore -srcalias $(subst wildcard,*,$(ALIAS)) \
		-srckeystore $(KEYSTORE) -srcstorepass $(PASSWORD) \
		-destkeystore "$(FOLDER)/$(BROWSER_CERT)" -deststorepass $(PASSWORD) \
		-deststoretype PKCS12

	@echo "Export $(ALIAS) public key"
	keytool -export -alias $(ALIAS) -file $(FOLDER)/k-$(ALIAS).crt -rfc \
		-keystore $(KEYSTORE) -storepass $(PASSWORD)

	@echo "Export $(ALIAS) certificate into .key"
	echo $(PASSWORD) > /tmp/pwd.txt
	openssl pkcs12 -in $(FOLDER)/$(BROWSER_CERT)  -nodes -nocerts -out $(FOLDER)/k-$(ALIAS).key -passin file:/tmp/pwd.txt
endef

## Create Keys
create-server-key:
	$(eval SAN=dns:$(HOSTNAME_SERVER))

	$(call generate_key,$(HOSTNAME_SERVER),$(DNAME_SERVER),\
	$(SAN),\
	$(KEYSTORE_SERVER),$(PASSWORD),$(FOLDER_SERVER_CERT))

create-clients-key:
	$(eval SAN=dns:$(ALIAS_CLIENT_ALICE))
	## Alice
	$(call generate_key,$(ALIAS_CLIENT_ALICE),$(DNAME_CLIENT_ALICE),\
	$(SAN),\
	$(KEYSTORE_CLIENTS),$(PASSWORD),$(FOLDER_CLIENTS_CERT))

	## Bob
	$(eval SAN=dns:$(ALIAS_CLIENT_BOB))
	$(call generate_key,$(ALIAS_CLIENT_BOB),$(DNAME_CLIENT_BOB),\
	$(SAN),\
	$(KEYSTORE_CLIENTS),$(PASSWORD),$(FOLDER_CLIENTS_CERT))

## Deploy

deploy:
	cp $(KEYSTORE_SERVER) ../src/main/resources/keystores/
	cp $(TRUSTSTORE) ../src/main/resources/keystores/

## Clean
clean:
	# Remove folters
	rm -rf ${FOLDER_GLOBAL}
	rm -rf ${FOLDER_SERVER_CERT}
	rm -rf ${FOLDER_CLIENTS_CERT}
