# TP17 : réponses aux questions

## Départ

L'application de départ (`latest`, conteneur `privileged`, exécution en root, aucune limite) et le Pod `intruder` sont **acceptés sans aucun avertissement** : sans admission ni NetworkPolicy, Kubernetes ne vérifie que la syntaxe.

## Partie 1 : RBAC

* **ServiceAccount `default`** : sur K3s, `auth can-i --list` ne montre que les droits de découverte (`selfsubjectreviews`, `selfsubjectaccessreviews`, `/api`, `/healthz`…), pas l'accès aux ressources. Mais son **jeton est monté par défaut** dans chaque Pod (`/var/run/secrets/kubernetes.io/serviceaccount/token`). Si un administrateur lui ajoute des droits, tous les Pods du namespace en héritent.
* **Résultats avec `api-sa`** : `get configmaps` dans tp17 → **yes** ; `list secrets` → **no** ; `get configmaps` dans `default` → **no** (un Role ne vaut que dans son namespace) ; `create pods` → **no**. C'est le **moindre privilège**.
* **`automountServiceAccountToken: false`** : l'API (whoami) n'appelle jamais l'API Kubernetes. Monter son jeton ne servirait qu'à un attaquant qui compromettrait le conteneur (lecture du jeton, puis appels à l'API server avec les droits du SA). Pas de jeton, pas de pivot.
* **Role / ClusterRole** : un *Role* définit des droits **dans un namespace** ; un *ClusterRole* définit des droits sur des ressources **non namespacées** (nodes, PV, CRD…) ou réutilisables dans tous les namespaces.
* **RoleBinding / ClusterRoleBinding** : un *RoleBinding* accorde un Role (ou un ClusterRole) **dans un seul namespace** ; un *ClusterRoleBinding* accorde un ClusterRole **sur tout le cluster**. Un RoleBinding vers le ClusterRole `view` donne donc la lecture d'un seul namespace.
* **`cluster-admin`** : `kubectl get clusterrolebindings -o wide | grep cluster-admin` montre notamment `cluster-admin` → groupe `system:masters` (le kubeconfig admin de K3s) et `helm-kube-system-traefik*` (K3s). Chaque binding vers `cluster-admin` est un accès total : il faut les recenser et les justifier.

## Partie 2 : securityContext

| Option | Protection |
|---|---|
| image taggée (`v1.10.1`) | déploiement reproductible, scan de vulnérabilités fiable |
| `privileged: false` | pas d'accès aux devices ni au noyau de l'hôte |
| `runAsNonRoot` / `runAsUser: 65532` | pas de root dans le conteneur, donc évasion plus difficile |
| `allowPrivilegeEscalation: false` | bloque setuid / `no_new_privs` |
| `readOnlyRootFilesystem: true` | impossible d'écrire un binaire ou de modifier la config |
| `capabilities.drop: ["ALL"]` | aucune capacité Linux (`NET_RAW`, `CHOWN`…) |
| `seccompProfile: RuntimeDefault` | filtre les appels système dangereux |
| requests / limits | pas de déni de service par épuisement des ressources |

* `id` dans le frontend → `uid=101(nginx)`. `touch /etc/test` → `Read-only file system`. Nginx écrit son PID et ses fichiers temporaires dans `/tmp` : un **volume `emptyDir`** y est monté (seul emplacement inscriptible).
* `nginxinc/nginx-unprivileged` écoute sur **8080** (port > 1024, pas besoin de `NET_BIND_SERVICE`). La variante `1.29-alpine` contient `wget` pour les tests réseau.

## Partie 3 : Pod Security Standards

* `warn` / `audit` : n'empêchent rien. `warn` affiche un avertissement au `kubectl apply`, `audit` l'écrit dans les logs d'audit. Ils permettent de voir **ce qui casserait** avant d'activer `enforce`.
* Après durcissement, `rollout restart` ne produit plus d'avertissement.
* En `enforce=restricted`, le Pod privilégié (`privileged`, `hostNetwork`, root, sans seccomp) est **refusé par l'API server** (`violates PodSecurity "restricted:latest"`). Les Pods déjà en place (l'`intruder`) ne sont pas supprimés, mais ne pourraient plus être recréés.

## Partie 4 : NetworkPolicies

* Sans policy, **tout Pod joint tout Pod** : l'intrus interroge l'API librement.
* `default-deny-all` (`podSelector: {}`, Ingress + Egress) bloque tout, **y compris le DNS** : `wget http://api` échoue dès la résolution du nom.
* On rouvre ensuite le strict nécessaire : DNS sortant vers les Pods `k8s-app=kube-dns` de `kube-system` (UDP/TCP 53), sortie du frontend vers l'api sur 8080, et entrée de l'api depuis le frontend sur 8080. Il faut **les deux côtés** (egress du client et ingress du serveur) quand tout est fermé par défaut.
* Les NetworkPolicies portent sur le **port du Pod** (8080), pas sur celui du Service (80) : le Service est traduit vers l'IP du Pod avant le filtrage.
* Résultat : frontend → api OK, intrus → api **timeout** (paquets ignorés, pas de refus explicite). Sur K3s, c'est le contrôleur NetworkPolicy intégré (kube-router) qui les applique.

## Partie 5 : Kyverno

* **Version** : Kyverno 1.20 n'exécute plus les `ClusterPolicy` (`kyverno.io/v1`) et impose les nouvelles `ValidatingPolicy` (CEL). Le TP utilise donc Kyverno **1.19.2** (chart 3.9.2) et la CLI de la même version.
* **Audit** : les violations sont seulement **rapportées** (`PolicyReport` par namespace, avec pass / fail par règle). Ce mode permet de mesurer l'écart avant de bloquer.
* **Résultats CLI** sur l'application de départ : `pass: 7, fail: 8` (api : latest + privileged + runAsNonRoot + resources ; frontend : runAsNonRoot + resources ; intruder : runAsNonRoot + resources). Application durcie : `fail: 0`. La CLI n'a pas besoin de cluster, donc elle s'intègre en CI pour bloquer une merge request **avant** le déploiement.
* **Enforce** : le webhook d'admission refuse `bad-app` avec les messages de toutes les règles violées. Grâce à l'**autogen**, une règle écrite pour les `Pod` s'applique aussi aux Deployments, StatefulSets et Jobs (le refus arrive dès le Deployment, pas seulement au niveau des Pods).
* Les policies ne ciblent que `tp17` : appliquées partout en Enforce, elles bloqueraient Falco ou Trivy Operator, qui ont légitimement besoin de privilèges.

| | Pod Security Standards | Kyverno |
|---|---|---|
| Intégration | native (API server), simple label | contrôleur + webhook à installer |
| Règles | 3 profils figés (privileged / baseline / restricted) | règles libres, écrites en YAML |
| Validation | oui | oui (Audit / Enforce, exceptions) |
| **Mutation** | non | oui (ex. ajouter `seccompProfile`, labels, sidecars) |
| **Génération** | non | oui (ex. créer une NetworkPolicy par défaut dans chaque nouveau namespace) |
| **Vérification d'images** | non | oui (signatures Cosign, attestations, registres autorisés) |
| **Règles métier** | non | oui (tag interdit, labels obligatoires, limites, Ingress…) |
| Rapports | logs d'audit | PolicyReports consultables avec kubectl |

PSS est la base minimale à activer partout ; Kyverno ajoute les règles propres à l'organisation.

## Partie 6 : analyse continue et détection

* **Trivy Operator** scanne en continu les images des Pods (**VulnerabilityReports** : CVE par sévérité, versions corrigées) et leur configuration (**ConfigAuditReports** : root, privilèges, limites…). L'application durcie a beaucoup moins de constats de configuration ; les CVE restantes dépendent des images de base.
* **Kubescape** (référentiel NSA-CISA) : score de conformité **avant** durcissement (`00-app.yaml`) nettement inférieur au score **après** (`01-app-hardened.yaml` + RBAC + NetworkPolicies). Les contrôles qui passent au vert : non-root, conteneur non privilégié, système de fichiers en lecture seule, capacités retirées, limites de ressources, NetworkPolicy présente, jeton de SA non monté.
* **Falco** observe les appels système dans le noyau (pilote **eBPF moderne**, sans module noyau). `cat /etc/shadow` dans l'intrus déclenche la règle *Sensitive file opened for reading by non-trusted program* (Warning) ; `kubectl exec -it … sh` déclenche *Terminal shell in container* (Notice). Grâce au socket containerd de K3s (`/run/k3s/containerd/containerd.sock`), les alertes indiquent le Pod et le namespace.
* Complémentarité : **avant** le déploiement (CLI Kyverno, Kubescape, Trivy en CI) → **à l'admission** (PSS, Kyverno) → **en fonctionnement** (Trivy Operator pour les nouvelles CVE, Falco pour les comportements anormaux). Aucune couche ne suffit seule : c'est la défense en profondeur.

## Défis

* **Mutation Kyverno** (`defi/mutate-seccomp.yaml`) : `+(seccompProfile)` ajoute `type: RuntimeDefault` uniquement s'il est absent, sans écraser une valeur existante. Testée avec la CLI : le Deployment `api` de départ reçoit bien `seccompProfile: RuntimeDefault`.
* **Gatekeeper** (`defi/gatekeeper/`) : la même règle demande un `ConstraintTemplate` (code **Rego** + schéma) et une `Constraint` (portée). La logique (vérifié avec `opa eval`) refuse `nginx:latest` et `nginx`, et accepte `nginx:1.29`. Comparaison : Rego est plus puissant (vrai langage de requête, réutilisable hors Kubernetes) mais demande d'apprendre un langage ; Kyverno s'écrit en YAML proche des manifests (patterns, `!*:latest`), donc plus lisible pour une équipe Kubernetes.
