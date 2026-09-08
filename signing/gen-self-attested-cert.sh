#!/bin/bash
# Regenerate the self-attested C2PA signing chain (ES256 / P-256).
#
# This is the PLACEHOLDER cert used until a CA-issued, C2PA-trust-listed
# certificate is obtained. It is self-attested: a local CA vouches for a leaf,
# and nothing vouches for the CA. Verifiers will report the signer as
# untrusted — expected and disclosed in every manifest.
#
# C2PA forbids a literally self-signed LEAF, so we build a two-cert chain:
#   dev_ca (self-signed root)  ->  es256 leaf (signed by the root)
# The leaf needs EKU emailProtection (id-kp-emailProtection) per the C2PA
# cert profile.
#
# Output (in this dir): es256_private.key (the signing key),
#   es256_certs.pem (leaf + CA chain, what c2patool uses as sign_cert).
#
# Run from the signing/ dir:  bash gen-self-attested-cert.sh
set -euo pipefail
cd "$(dirname "$0")"

ORG="SessionSeal"
CA_CN="SessionSeal Self-Attested CA"
LEAF_CN="SessionSeal Self-Attested Signer"
DAYS=3650

# --- root CA -----------------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out dev_ca_private.key
openssl req -x509 -new -key dev_ca_private.key -sha256 -days "$DAYS" \
  -out dev_ca_cert.pem \
  -subj "/O=${ORG}/CN=${CA_CN}"

# --- leaf signing cert -------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out es256_private.key
openssl req -new -key es256_private.key -out es256_leaf.csr \
  -subj "/O=${ORG}/CN=${LEAF_CN}"

cat > es256_leaf.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=emailProtection
EXT

openssl x509 -req -in es256_leaf.csr \
  -CA dev_ca_cert.pem -CAkey dev_ca_private.key -CAcreateserial \
  -sha256 -days "$DAYS" -extfile es256_leaf.ext \
  -out es256_cert_leaf.pem

# --- chain c2patool uses (leaf first, then CA) -------------------------------
cat es256_cert_leaf.pem dev_ca_cert.pem > es256_certs.pem

rm -f es256_leaf.csr es256_leaf.ext
chmod 600 es256_private.key dev_ca_private.key

echo "Generated. Leaf subject:"
openssl x509 -in es256_cert_leaf.pem -noout -subject
