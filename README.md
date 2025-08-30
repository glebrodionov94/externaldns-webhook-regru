# external-dns-regru-webhook — Quick Install (Helm-only)

Webhook для ExternalDNS, который управляет DNS в REG.RU через их API.

> Требуется активированный доступ к REG.RU API c правами на управление DNS для доменов. Иначе обновления не применятся.

## 0) Добавляем Helm-репозитории

> Репозиторий для webhook — фиктивный для примера. Замените на свой.

```bash
helm repo add regru-webhook https://charts.example.org/regru-webhook
helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/
helm repo update
```

## 1) Устанавливаем **webhook** (через Helm)

Создайте `values-webhook.yaml` (оставлены только ключи с реальными значениями):

```yaml
image:
  repository: my.registry.local/external-dns-regru-webhook
  tag: latest
  pullPolicy: IfNotPresent

service:
  port: 8888

env:
  - name: REGRU_USERNAME
    valueFrom:
      secretKeyRef:
        name: regru-credentials
        key: username
  - name: REGRU_PASSWORD
    valueFrom:
      secretKeyRef:
        name: regru-credentials
        key: password
  - name: REGRU_API_URL
    value: https://api.reg.ru/api/regru2
  - name: DOMAIN_FILTERS
    value: example.org,example.net
  - name: DEFAULT_TTL
    value: "300"
  - name: CACHE_TTL_SECONDS
    value: "60"
  - name: CACHE_MAX_ZONES
    value: "100"

# Создание секрета силами чарта (если ваш чарт это поддерживает)
secretConfiguration:
  enabled: true
  data:
    username: my-login@example.org
    password: my-super-secret
```

Установка:

```bash
helm upgrade --install regru-webhook regru-webhook/regru-webhook -f values-webhook.yaml -n default
```

После установки сервис будет доступен по DNS-имени:

```
http://regru-webhook.default.svc.cluster.local:8888
```

## 2) Устанавливаем **ExternalDNS** (ванильный образ + webhook-provider)

Создайте `values-externaldns.yaml` (только значимые ключи):

```yaml
domainFilters:
  - example.org
  - example.net

interval: 1m
logLevel: info
policy: upsert-only

sources:
  - ingress

managedRecordTypes:
  - A
  # добавьте "CNAME", "TXT" и т.п., когда будете готовы их управлять

image:
  repository: registry.k8s.io/external-dns/external-dns
  tag: v0.15.0 # пример; укажите актуальную версию
  pullPolicy: IfNotPresent

provider:
  name: webhook

extraArgs:
    - '--webhook-provider-url=http://127.0.0.1:8888'

txtOwnerId: external-dns-demo
```

Установка:

```bash
helm upgrade --install external-dns external-dns/external-dns -f values-externaldns.yaml -n default
```

## 3) Проверка

```bash
kubectl get pods -n default -l app.kubernetes.io/name=external-dns
kubectl get pods -n default -l app=regru-webhook
kubectl port-forward -n default svc/regru-webhook 8888:8888
curl -s http://127.0.0.1:8888/healthz
```

Ожидаемый ответ:

```json
{"ok":true,"zones_cached":[]}
```

Готово! ExternalDNS теперь будет синхронизировать DNS для `example.org` и `example.net` через ваш webhook и REG.RU API.
