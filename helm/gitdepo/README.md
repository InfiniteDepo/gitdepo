# gitdepo Helm chart

Installs one gitdepo instance (rootless image, one replica, `Recreate`) with a PersistentVolumeClaim for `/var/lib/gitea`. The database is an external PostgreSQL server; there is no bundled one. High availability is not supported yet.

## Install

```sh
kubectl create namespace gitdepo
kubectl -n gitdepo create secret generic gitdepo-db --from-literal=password='<database password>'
# Optional but recommended: a fixed SECRET_KEY also locks the web installer.
kubectl -n gitdepo create secret generic gitdepo-secrets --from-literal=SECRET_KEY="$(openssl rand -hex 32)"

helm install gitdepo ./helm/gitdepo -n gitdepo \
  --set rootUrl=https://git.example.com/ \
  --set database.host=postgres.example.com:5432 \
  --set database.existingSecret=gitdepo-db \
  --set 'extraEnvFrom[0].secretRef.name=gitdepo-secrets'
```

`rootUrl`, `database.host` and `database.existingSecret` are required. Without `SECRET_KEY` the web installer opens at the URL; with it, create the first administrator as `NOTES.txt` shows (`gitea admin user create --admin ...`).

## Values

See [`values.yaml`](values.yaml). The main ones:

| Value | Meaning |
| --- | --- |
| `image.tag` | Image tag, default the chart's `appVersion` |
| `database.*` | PostgreSQL host, name, user, `sslMode`; the password comes from `existingSecret` / `secretKey` |
| `config.<section>.<KEY>` | Any `app.ini` setting, as `GITEA__SECTION__KEY` (dots in a section become `_0X2E_`) |
| `extraEnv`, `extraEnvFrom` | More variables, for secrets (`secretKeyRef`, `secretRef`); never put secrets in `config` |
| `persistence.*` | Size, `storageClassName`, `existingClaim` |
| `service.http`, `service.ssh` | `type` and `annotations`; SSH is a separate Service, off by default |
| `ingress.*` | `className`, `annotations`, `hosts`, `tls` |
| `serviceAccount.annotations` | Workload identity |

SSH is served by gitdepo itself on container port 2222. Set `sshDomain` (and `sshPort` if the load balancer isn't on 22) so clone URLs are right.

## Per cloud

Example files: [`examples/values-aks.yaml`](examples/values-aks.yaml), [`values-eks.yaml`](examples/values-eks.yaml), [`values-gke.yaml`](examples/values-gke.yaml). Use them with `helm install ... -f examples/values-<cloud>.yaml`; replace the `example.com` names and IDs.

| | AKS | EKS | GKE |
| --- | --- | --- | --- |
| Storage class | `managed-csi-premium` (Azure Disk) | `gp3` (EBS CSI driver add-on) | `premium-rwo` (Persistent Disk) |
| Ingress | `nginx` (ingress-nginx) | `alb` (AWS Load Balancer Controller) | `gce` (needs `cloud.google.com/neg` on the HTTP Service) |
| SSH load balancer | Azure Load Balancer; `externalTrafficPolicy: Local` | NLB via the controller annotations | External TCP load balancer |
| PostgreSQL | Azure Database for PostgreSQL flexible server | Amazon RDS | Cloud SQL (private IP or Auth Proxy) |
| Workload identity | `azure.workload.identity/client-id` annotation and `azure.workload.identity/use` pod label | `eks.amazonaws.com/role-arn` (IRSA) | `iam.gke.io/gcp-service-account` |

Use `sslMode: require` (the default) or `verify-full` for managed PostgreSQL. A block-storage volume can attach to one node, which fits the single replica; `Recreate` makes sure the old pod lets go of it first.

## Upgrade and uninstall

`helm upgrade` with a new `image.tag` migrates the database on start. The PVC isn't removed by `helm uninstall` when you use `existingClaim`; otherwise delete it yourself to drop the data.
