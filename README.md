# external-dns-regru-webhook — Quick Install (Helm-only)

## 1) Подготовьте `values.yaml`

Скопируйте ниже в `values.yaml`.
Здесь же, в `extraObjects`, мы создаём Secret с логином/паролем REG.RU, чтобы установка была **полностью через Helm**.

```yaml
# Используем официальный образ ExternalDNS (НЕ Bitnami)
image:
  repository: registry.k8s.io/external-dns/external-dns
  pullPolicy: IfNotPresent
# Если нужен доступ к приватным реестрам:
# imagePullSecrets:
#   - name: my-regcred

# Какие домены обслуживать
domainFilters:
  - example.org
  - example.net

# Частота синхронизации и базовые настройки
interval: 1m
logLevel: info
policy: upsert-only

# Откуда брать объекты для генерации DNS-записей
sources:
  - ingress

# Какие типы записей управляем (минимально — A)
managedRecordTypes:
  - A
  # добавьте CNAME/TXT/etc при необходимости

# Вебхук-провайдер (разворачивается этим же Helm-чартом)
provider:
  name: webhook
  webhook:
    # Переменные окружения для вебхука
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
    # Образ вебхука (ваш реестр)
    image:
      repository: my.registry.local/regru/external-dns-regru-webhook
      tag: v1.0.0
      pullPolicy: IfNotPresent
    # Порт сервиса вебхука внутри кластера
    service:
      port: 8888

# Идентификатор для TXT-записей ExternalDNS (чтобы не конфликтовать с другими инсталляциями)
txtOwnerId: external-dns-example

# Полностью через Helm: создаём Secret с кредами REG.RU
extraObjects:
  - apiVersion: v1
    kind: Secret
    metadata:
      name: regru-credentials
    type: Opaque
    stringData:
      username: login@example.org
      password: "s3cr3t-password"
```

> Если вебхук-образ приватный — добавьте `imagePullSecrets` на уровень `spec` кластера/неймспейса или используйте возможности чарта (в примере выше поле закомментировано).

---

## 2) Установите ExternalDNS + вебхук одной командой

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm upgrade --install external-dns bitnami/external-dns -f values.yaml
```

Проверка, что вебхук жив (подставьте ваш namespace, если он не `default`):

```bash
kubectl get deploy,svc | grep external-dns-regru-webhook
kubectl run curl --rm -it --image=curlimages/curl --restart=Never -- \
  curl -s http://external-dns-regru-webhook.default.svc.cluster.local:8888/healthz
```

Ожидаемый ответ:

```json
{"ok":true,"zones_cached":[]}
```

---

## Готово

* ExternalDNS будет брать объекты из `Ingress` и управлять DNS для `example.org` и `example.net` через ваш вебхук.
* Для изменений записей у домена должен быть включён доступ к REG.RU API с правами управления DNS (часто это отдельная платная опция у провайдера).
