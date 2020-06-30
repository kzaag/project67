# Development certificates and keys used in testing.

# Do not use in the production server!!!!

# In the production server it is highly recommended to get in touch with professional CA
# and obtain some well known root CA certificate.

# hint: if you go with Let's encrypt then you might want to use DST Root CA x3 certficate.
#            (hint x2: /etc/ssl/certs/DST_Root_CA_X3.pem)

# vattd

set -e

cd $1/bin

echo "[req]
prompt = no
distinguished_name = dn
req_extensions = req_ext

[dn]
CN=IN
O=invigilare

[req_ext]
subjectAltName=@an

[an]
IP.1=127.0.0.1" > .cnf

# ---- begin ca ---- 

openssl ecparam -genkey -name secp384r1 -out ca_private_key

openssl req -x509 -new -batch -key ca_private_key -sha512 -days 100 -out chain.pem

# ---- end ca ----

# ---- begin csr ----

openssl ecparam -genkey -name secp384r1 -out server_private_key

openssl req -new -batch -key server_private_key -out .csr -config .cnf

# ---- end csr ----

openssl x509 -req -days 100 -in .csr -CA chain.pem -CAkey ca_private_key \
        -out server_cert.pem -CAcreateserial -extensions req_ext -extfile .cnf > /dev/null 2>&1;

# ---- begin generate default certs ---- #

./p67gencert > /dev/null;

# ---- end generate default certs ---- #


rm .csr;
rm .cnf;
rm *.srl

