# Défi Gatekeeper (namespace de test uniquement)

```bash
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts && helm repo update
helm install gatekeeper gatekeeper/gatekeeper -n gatekeeper-system --create-namespace
kubectl create ns gk-test
kubectl apply -f defi/gatekeeper/template.yaml
sleep 10
kubectl apply -f defi/gatekeeper/constraint.yaml
kubectl -n gk-test run t1 --image=nginx:latest      # refusé : tag latest
kubectl -n gk-test run t2 --image=nginx             # refusé : pas de tag
kubectl -n gk-test run t3 --image=nginx:1.29-alpine # accepté
# Nettoyage
kubectl delete ns gk-test && helm uninstall gatekeeper -n gatekeeper-system
```
