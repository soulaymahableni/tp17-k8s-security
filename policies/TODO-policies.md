# Policies à écrire (Partie 5) : faites

| Fichier | Règle | Message de refus |
|---|---|---|
| `disallow-latest-tag.yaml` (modèle) | image taggée, pas de `latest` | « Le tag 'latest' est interdit… » |
| `disallow-privileged.yaml` | `securityContext.privileged` absent ou `false` | « Les conteneurs privilégiés sont interdits… » |
| `require-run-as-nonroot.yaml` | `runAsNonRoot: true` (Pod ou chaque conteneur) | « runAsNonRoot doit valoir true… » |
| `require-requests-limits.yaml` | `requests.cpu`, `requests.memory`, `limits.memory` | « Chaque conteneur doit définir… » |

Toutes les policies ciblent uniquement le namespace `tp17` (Kyverno ne doit pas bloquer
Falco, Trivy Operator ou les composants système, qui ont besoin de privilèges).

Passage en Enforce :

```bash
sed -i 's/failureAction: Audit/failureAction: Enforce/' policies/*.yaml
kubectl apply -f policies/
```
