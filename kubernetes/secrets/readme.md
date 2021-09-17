## Secrets

Example files for populating Kubernetes with secrets

### Environment

Files generated within Docker container:

```
docker run -it -w $(pwd) -v $(pwd):$(pwd) ubuntu /bin/bash
```

Installing tools:

```
apt update && apt install -y openssl openssh-client 
```

### Generating

ssh keys:
```
ssh-keygen -t rsa -f ./secrets/id-rsa-with-passphrase -N 'helloworld' <<< y
ssh-keygen -t rsa -f ./secrets/id-rsa-without-passphrase -N '' <<< y

ssh-keygen -t ed25519 -f ./secrets/id-ed25519-with-passphrase -N 'helloworld' <<< y
ssh-keygen -t ed25519 -f ./secrets/id-ed25519-without-passphrase -N '' <<< y
```

tls:
```
openssl genrsa -out ./secrets/ca.key 2048
openssl req -x509 -new -nodes -days 365 -key ./secrets/ca.key -out ./secrets/ca.crt -subj "/CN=example.com"
```
