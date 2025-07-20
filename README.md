# tf-eks-pod-identity

```sh
AWS_PROFILE=example
aws sso login
aws eks update-kubeconfig --region ap-northeast-1 --name kaita-self-mng --profile example
```

```sh
kubectl logs -l app=aws-cli-0
kubectl delete po -l app=aws-cli-0
```
