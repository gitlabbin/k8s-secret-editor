# k8s-secret-editor
Secret Editor Web interface for Kubernetes

This is a web tool to edit [Secrets](http://kubernetes.io/docs/user-guide/secrets/) in Kubernetes. A secret is a resource which contains one or several files encoded inside, which are then mounted to a pod. Defining those files within a YAML is complicated so we created this tool to edit them directly in the browser.

The application is plug & play. It uses K8S' service accounts to access the cluster, so no more configuration is needed.

![alt tag](https://raw.githubusercontent.com/bq/k8s-secret-editor/master/docs/screenshot.png)

# How to deploy

We offer two options:

### Directly deploy

We include YAMLs to directly deploy this tool in Kubernetes:

```
kubectl create -f k8s-secrets-editor.yml
```

( If your kubernetes cluster version < 1.6  )
```
kubectl create -f pre16-k8s-secrets-editor.yml
```

And enjoy it at http://SERVICE_IP_ADDRESS or mapping the port to your local

```
kubectl --namespace kube-system port-forward <POD_NAME> 8080:80
```

### Just pull the image

You can also just pull the Docker image (bqitdevops/k8s-secret-editor) and deploy on your own.

It will only work if deployed to Kubernetes as it uses injected service account and environment variables to connect to K8S API service.

```
docker pull bqitdevops/k8s-secret-editor
```

# Authentication
As it will be used to manage sensitive information, we secured the access to the web with basic http authentication:
* User: *admin*
* Password: Defined in the environment variable ADMIN_PASSWORD. If you are deploying with the file k8s-deployment.yaml, by default it is *admin*

# Helm chart doc
https://helm.sh/docs/chart_template_guide/variables/
