## Pods

Create resources:

```
kubectl apply -f redis.yaml
kubectl apply -f thinkphp.yaml
```

Ensure pods are alive:

```
kubectl describe pods
```

Interacting with a pod:

```
kubectl exec -it redis -- /bin/sh
```

Getting a JWT token for the kube-system namespace:

```
kubectl -n kube-system describe secret default

# For use in CURLs
jwt_token=$(kubectl get secret -n kube-system $(kubectl -n kube-system get serviceaccount default -o jsonpath="{.secrets[0].name}") -o jsonpath="{.data.token}" | base64 --decode)

echo $jwt_token
```

## Secrets

Create resources:

```
kubectl apply -f secrets.yaml

kubectl create secret generic secret-empty

kubectl create secret generic secret-id-rsa-with-passphrase --from-file=ssh-privatekey=./secrets/id-rsa-with-passphrase --type=kubernetes.io/ssh-auth
kubectl create secret generic secret-id-rsa-without-passphrase --from-file=ssh-privatekey=./secrets/id-rsa-without-passphrase --type=kubernetes.io/ssh-auth

kubectl create secret generic secret-id-ed25519-with-passphrase --from-file=ssh-privatekey=./secrets/id-rsa-with-passphrase --type=kubernetes.io/ssh-auth
kubectl create secret generic secret-id-ed25519-without-passphrase --from-file=ssh-privatekey=./secrets/id-rsa-without-passphrase --type=kubernetes.io/ssh-auth

kubectl create secret docker-registry secret-local-registry --docker-username=username --docker-password=password --docker-email=admin@example.com

kubectl create secret tls secret-tls --key ./secrets/ca.key --cert ./secrets/ca.crt
```

To populate a lot of secrets, for testing purposes:

```
for i in {1..2000}; do kubectl create secret generic secret-basic-auth-$i --from-literal=username=username-${i} --from-literal=password=password-${i} --type="kubernetes.io/basic-auth"; done 
```

Checking secrets:
```
kubectl describe secrets
```

Checking config maps which may also have sensitive information:

```
kubectl describe configmap
```

Dumping JSON:
```
kubectl describe configmap -o json
```

Deleting
```
kubectl delete secrets --all
```

## Thinkphp session

Ensure the pod has been created and alive:
```
kubectl apply -f thinkphp.yaml
kubectl get deployments thinkphp
```

Access the pod from localhost, in lieu of setting up ingress properly:

```
kubectl port-forward thinkphp-67f7c88cc9-djg6q 8000:80
```

Run the Metasploit exploit module:

```
use exploit/unix/webapp/thinkphp_rce
run http://localhost:8000
```

Acquire a shell, and verify the service token is in the container:
```
cat /run/secrets/kubernetes.io/serviceaccount/token
```

## Testing volume exploit

```
kubectl delete pod generate-this-later-pod 2>/dev/null; kubectl apply -f ./exploit.yml
```

Directly interacting with it:
```
kubectl exec -it generate-this-later-pod -- /bin/sh
```

## API

The OpenAPI approach looks interesting, as we can generate clients in the same way as Swagger:

https://kubernetes.io/blog/2016/12/kubernetes-supports-openapi/

Generated:

https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/

Client examples:
https://github.com/kubernetes-client

Note that the namespace would be in the URI `api/v1/namespaces/{namespace_name}/`
You can also retrieve the list of namespaces locally with:

```
kubectl get namespaces
kubectl get namespaces -o json
```

### JWT_TOKEN

Note that the curl examples assume the `jwt_token` is set.

If you're on your host with `kubectl` available:

```
jwt_token=$(kubectl get secret -n kube-system $(kubectl -n kube-system get serviceaccount default -o jsonpath="{.secrets[0].name}") -o jsonpath="{.data.token}" | base64 --decode)

echo $jwt_token
```

If you're in a container already:

```
jwt_token=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
echo $jwt_token
```

### Get namespaces

```
curl --insecure --request GET \
--url 'https://kubernetes.docker.internal:6443/api/v1/namespaces' \
--header "Authorization: Bearer ${jwt_token}"
```

### Get PODs

```
curl --insecure --request GET \
  --url 'https://kubernetes.docker.internal:6443/api/v1/namespaces/default/pods' \
  --header "Authorization: Bearer ${jwt_token}"
```

### Get Secrets

```
curl --insecure --request GET \
  --url 'https://kubernetes.docker.internal:6443/api/v1/namespaces/default/secrets' \
  --header "Authorization: Bearer ${jwt_token}"
```

### Get Configmaps

```
curl --insecure --request GET \
  --url 'https://kubernetes.docker.internal:6443/api/v1/namespaces/default/configmaps' \
  --header "Authorization: Bearer ${jwt_token}"
```

### Create a pod

```
yq -o json e ./exploit.yml |
  curl --insecure -v --request POST \
    --url 'https://kubernetes.docker.internal:6443/api/v1/namespaces/default/pods' \
    --header "Authorization: Bearer ${jwt_token}" \
    --header 'Content-Type: application/json' \
    --data @-
```

### Management

Clean up:

```
kubectl delete deployments,pods,services --all
```

Delete all CrashLooping pods:

```
kubectl delete pod `kubectl get pods | awk '$3 == "CrashLoopBackOff" {print $1}'`
```

Running the Kubernetes [Dashboard UI](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/):

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.3.1/aio/deploy/recommended.yaml

kubectl proxy
```

Now visit:

http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/#/login

To login, use the `jwt_token` mentioned above

### Ideas

Spencer
- Confirm Comm semantics for send_cgi
- Decide on how we want to get additional sessions, i.e. docker pod cmd, exec + mettle, or exec + stream
- If we have a long lived attacker pod, we could continually exec new payloads against it. We'd need to keep track of it for reuse and cleanup.
        - Pod exec example: https://github.com/kubernetes-client/python/blob/master/examples/pod_exec.py#L84-L90
        - https://github.com/kubernetes-client/python-base/blob/master/stream/stream.py#L34

Alan
- Update sysinfo to detect if you're in docker/kubernetes
- Pull out the secrets information / env / ConfigMaps
- Get access to a real cluster

TODO: ENV will disappear from the container if you upgrade a shell to meterpreter
