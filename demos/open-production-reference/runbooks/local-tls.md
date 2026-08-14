# Local TLS

Create an isolated evaluator CA. Do not reuse these keys outside the local
stack and do not commit generated files.

```text
cd demos/open-production-reference/compose
openssl req -x509 -newkey rsa:3072 -nodes -days 7 -subj /CN=auths-local-ca -keyout postgres/certs/ca.key -out postgres/certs/ca.crt
openssl req -newkey rsa:3072 -nodes -subj /CN=postgres -keyout postgres/certs/server.key -out postgres/certs/server.csr
openssl x509 -req -days 7 -in postgres/certs/server.csr -CA postgres/certs/ca.crt -CAkey postgres/certs/ca.key -CAcreateserial -out postgres/certs/server.crt -extfile <(printf 'subjectAltName=DNS:postgres')
chmod 600 postgres/certs/server.key
openssl req -newkey rsa:3072 -nodes -subj /CN=localhost -keyout ingress/certs/server.key -out ingress/certs/server.csr
openssl x509 -req -days 7 -in ingress/certs/server.csr -CA postgres/certs/ca.crt -CAkey postgres/certs/ca.key -CAcreateserial -out ingress/certs/server.crt -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1')
```

Trust `postgres/certs/ca.crt` only in the client used for the evaluator. Remove
the generated CA and server keys when the stack is destroyed.
