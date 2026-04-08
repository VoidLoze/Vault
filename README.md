# Лабораторная №5: Vault + Docker Registry + Jenkins + mTLS

## Архитектура

```
Vault (CA + KV + AppRole)
  ├── выпускает TLS-сертификаты для всех компонентов
  ├── хранит пароли registry (bcrypt в htpasswd, plaintext в KV)
  └── выдаёт AppRole credentials Jenkins'у

Jenkins (AppRole auth)
  ├── получает из Vault: клиентский сертификат (TTL 24h) + пароль writer
  ├── подключается к Docker daemon по mTLS (TCP 2376)
  └── пушит образ в Registry (HTTPS, htpasswd)

Docker daemon (TCP 2376 + mTLS)
  └── сертификат от Vault CA, проверяет клиентский cert Jenkins'а

Docker Registry (HTTPS + htpasswd)
  ├── reader: только pull
  └── writer: push + pull
```

## Быстрый старт

### 1. Клонируй репозиторий приложения
Положи `Dockerfile` из прошлой лабы рядом с `Jenkinsfile`:
```
lab5/
├── Jenkinsfile        ← уже создан
├── Dockerfile         ← скопируй из прошлой лабы
└── src/               ← исходники приложения
```

### 2. Обнови URL репозитория в Jenkins CasC
В файле `jenkins/casc.yaml` замени:
```yaml
url('https://github.com/YOUR_ORG/YOUR_APP_REPO.git')
```

### 3. Запусти инфраструктуру
```bash
chmod +x scripts/start.sh
./scripts/start.sh
```

Скрипт автоматически:
- Запустит Vault и проведёт инициализацию (3 ключа, порог 2)
- Создаст корневой + промежуточный CA
- Выпустит TLS-сертификаты для daemon и registry
- Сгенерирует пароли пользователей registry (bcrypt в htpasswd)
- Настроит AppRole для Jenkins
- **Отзовёт root-токен**
- Запустит все сервисы

### 4. Доступ к сервисам

| Сервис       | URL                        | Credentials       |
|--------------|----------------------------|-------------------|
| Jenkins      | http://localhost:8080      | admin / admin123  |
| Vault UI     | http://localhost:8200      | unseal key + token|
| Registry     | https://localhost:5000     | reader / writer   |

### 5. Запуск pipeline
В Jenkins UI: открой `build-quarkus-app` → `Build Now`

## Структура файлов

```
lab5/
├── docker-compose.yml          # Все сервисы
├── .env                        # AppRole creds (автогенерируется)
├── .env.example                # Шаблон
├── .gitignore                  # Защита секретов
├── Jenkinsfile                 # Pipeline
├── vault/
│   └── init.sh                 # Полная инициализация Vault
├── jenkins/
│   ├── Dockerfile              # Jenkins + Docker CLI + Vault CLI
│   └── casc.yaml               # Configuration as Code
├── registry/
│   └── auth/
│       └── htpasswd            # Генерируется vault-init
├── certs/                      # Генерируется vault-init (в .gitignore!)
│   ├── ca/ca.crt
│   ├── registry/
│   ├── docker-daemon/
│   ├── unseal_key_[1-3].txt
│   ├── jenkins_role_id.txt
│   └── jenkins_secret_id.txt
└── scripts/
    └── start.sh                # Скрипт запуска
```

## Ключевые аспекты безопасности

### Vault
- Инициализация: 3 ключа, порог 2 (Shamir Secret Sharing)
- Root-токен отзывается после настройки
- Jenkins работает только через AppRole с минимальными правами
- PKI: корневой CA → промежуточный CA → сертификаты компонентов

### mTLS для Docker daemon
- Daemon принимает только соединения с клиентским сертификатом от нашего CA
- Клиентский сертификат Jenkins выпускается на TTL 24h
- Сертификат нигде не сохраняется между сборками

### Registry
- HTTPS с сертификатом от Vault CA
- Аутентификация через htpasswd (bcrypt)
- reader: только pull; writer: push + pull

### Jenkins
- `VAULT_ROLE_ID` и `VAULT_SECRET_ID` — через env vars Docker Compose (в prod: Docker Secret)
- Пароли получаются из Vault через `withVault{}` блок — Jenkins автоматически маскирует их в логах
- Клиентский сертификат создаётся в `$WORKSPACE/.certs` и удаляется в `post.always`

## Устранение неполадок

### Vault запечатан после перезапуска
```bash
# Нужно снова распечатать 2 из 3 ключей
docker exec -it vault vault operator unseal $(cat certs/unseal_key_1.txt)
docker exec -it vault vault operator unseal $(cat certs/unseal_key_2.txt)
```

### Сертификаты истекли (TTL)
```bash
# Перегенерировать: остановить vault-init контейнер и запустить заново
docker-compose rm -f vault-init
docker-compose up vault-init
```

### Проверить mTLS вручную
```bash
docker --tlsverify \
  --tlscacert certs/ca/ca.crt \
  --tlscert certs/docker-daemon/daemon.crt \
  --tlskey certs/docker-daemon/daemon.key \
  -H tcp://localhost:2376 \
  info
```
