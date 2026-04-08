#!/bin/sh
# =============================================================
# vault/init.sh — Полная инициализация Vault
# Запускается один раз в контейнере vault-init
# =============================================================
set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
CERTS_DIR="/certs"
REG_AUTH_DIR="/registry-auth"

log() { echo "[vault-init] $*"; }

# Ждём, пока Vault поднимется
wait_vault() {
  log "Ожидание Vault..."
  for i in $(seq 1 30); do
    # vault status returns non-zero when Vault is sealed, but API is reachable.
    # Treat any "Initialized/Sealed" response as ready.
    if vault status -address="$VAULT_ADDR" 2>&1 | grep -qE 'Initialized|Sealed'; then
      return 0
    fi
    sleep 2
  done
  echo "Vault не ответил за 60 секунд" && exit 1
}

# ------------------------------------------------------------------
# Шаг 1: Инициализация с 3 ключами, порог = 2
# ------------------------------------------------------------------
init_vault() {
  STATUS=$(vault status -address="$VAULT_ADDR" -format=json 2>/dev/null || true)
  INITIALIZED=$(echo "$STATUS" | grep -o '"initialized":[^,}]*' | cut -d: -f2 | tr -d ' ')

  if [ "$INITIALIZED" = "true" ]; then
    log "Vault уже инициализирован, пропускаем init"
    # Читаем сохранённые ключи
    UNSEAL_KEY_1=$(cat /certs/unseal_key_1.txt 2>/dev/null || true)
    UNSEAL_KEY_2=$(cat /certs/unseal_key_2.txt 2>/dev/null || true)
    ROOT_TOKEN=$(cat /certs/root_token.txt 2>/dev/null || true)
  else
    log "Инициализация Vault (3 ключа, порог 2)..."
    INIT_OUTPUT=$(vault operator init \
      -address="$VAULT_ADDR" \
      -key-shares=3 \
      -key-threshold=2)

    # Parse human-readable output (works reliably with BusyBox tools).
    UNSEAL_KEY_1=$(echo "$INIT_OUTPUT" | awk -F': ' '/Unseal Key 1/{print $2; exit}')
    UNSEAL_KEY_2=$(echo "$INIT_OUTPUT" | awk -F': ' '/Unseal Key 2/{print $2; exit}')
    UNSEAL_KEY_3=$(echo "$INIT_OUTPUT" | awk -F': ' '/Unseal Key 3/{print $2; exit}')
    ROOT_TOKEN=$(echo "$INIT_OUTPUT" | awk -F': ' '/Initial Root Token/{print $2; exit}')

    if [ -z "$UNSEAL_KEY_1" ] || [ -z "$UNSEAL_KEY_2" ] || [ -z "$ROOT_TOKEN" ]; then
      echo "Не удалось распарсить ключи/токен из vault operator init" >&2
      exit 1
    fi

    mkdir -p "$CERTS_DIR"
    echo "$UNSEAL_KEY_1" > "$CERTS_DIR/unseal_key_1.txt"
    echo "$UNSEAL_KEY_2" > "$CERTS_DIR/unseal_key_2.txt"
    echo "$UNSEAL_KEY_3" > "$CERTS_DIR/unseal_key_3.txt"
    echo "$ROOT_TOKEN"   > "$CERTS_DIR/root_token.txt"
    chmod 600 "$CERTS_DIR"/*.txt

    log "Ключи unseal сохранены в $CERTS_DIR/"
  fi

  export UNSEAL_KEY_1 UNSEAL_KEY_2 ROOT_TOKEN
}

# ------------------------------------------------------------------
# Шаг 2: Unseal (2 из 3 ключей)
# ------------------------------------------------------------------
unseal_vault() {
  SEALED=$(vault status -address="$VAULT_ADDR" -format=json 2>/dev/null | grep -o '"sealed":[^,}]*' | cut -d: -f2 | tr -d ' ')
  if [ "$SEALED" = "false" ]; then
    log "Vault уже распечатан"
    return 0
  fi
  if [ -z "$UNSEAL_KEY_1" ] || [ -z "$UNSEAL_KEY_2" ]; then
    echo "UNSEAL_KEY_1/UNSEAL_KEY_2 пустые. Нужен чистый re-init Vault и пересоздание /certs." >&2
    exit 1
  fi
  log "Распечатывание Vault (unseal)..."
  vault operator unseal -address="$VAULT_ADDR" "$UNSEAL_KEY_1"
  vault operator unseal -address="$VAULT_ADDR" "$UNSEAL_KEY_2"
  log "Vault распечатан"
}

# ------------------------------------------------------------------
# Шаг 3: Настройка PKI — корневой CA
# ------------------------------------------------------------------
setup_pki() {
  export VAULT_TOKEN="$ROOT_TOKEN"

  if ! vault secrets list -address="$VAULT_ADDR" | grep -q "^pki/"; then
    log "Включаем PKI secrets engine..."
    vault secrets enable -address="$VAULT_ADDR" -path=pki pki
    vault secrets tune -address="$VAULT_ADDR" -max-lease-ttl=87600h pki

    log "Генерируем корневой CA..."
    vault write -address="$VAULT_ADDR" -field=certificate pki/root/generate/internal \
      common_name="Lab5 Root CA" \
      issuer_name="root-ca" \
      ttl=87600h > "$CERTS_DIR/ca.crt"
  fi

  vault write -address="$VAULT_ADDR" pki/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

  # Промежуточный CA для выдачи сертификатов компонентам
  if ! vault secrets list -address="$VAULT_ADDR" | grep -q "^pki_int/"; then
    vault secrets enable -address="$VAULT_ADDR" -path=pki_int pki
    vault secrets tune -address="$VAULT_ADDR" -max-lease-ttl=43800h pki_int
  fi

  CURRENT_ISSUER_ID=$(
    vault list -address="$VAULT_ADDR" pki_int/issuers 2>/dev/null | \
    awk '/^----/{getline; if (NF) {print $1; exit}}'
  )

  if [ -z "$CURRENT_ISSUER_ID" ] || [ "$CURRENT_ISSUER_ID" = "default" ]; then
    log "Генерируем промежуточный CA..."
    vault write -address="$VAULT_ADDR" -field=csr pki_int/intermediate/generate/internal \
      common_name="Lab5 Intermediate CA" > /tmp/pki_int.csr

    vault write -address="$VAULT_ADDR" -field=certificate pki/root/sign-intermediate \
      csr=@/tmp/pki_int.csr \
      format=pem_bundle \
      ttl=43800h > /tmp/pki_int.crt

    vault write -address="$VAULT_ADDR" pki_int/intermediate/set-signed certificate=@/tmp/pki_int.crt
  fi

  # Vault 1.17 requires explicit default issuer for issuing certs.
  DEFAULT_ISSUER_ID=$(
    vault list -address="$VAULT_ADDR" pki_int/issuers 2>/dev/null | \
    awk '/^----/{getline; if (NF) {print $1; exit}}'
  )
  if [ -n "$DEFAULT_ISSUER_ID" ] && [ "$DEFAULT_ISSUER_ID" != "default" ]; then
    vault write -address="$VAULT_ADDR" pki_int/config/issuers default="$DEFAULT_ISSUER_ID" >/dev/null
  fi

  vault write -address="$VAULT_ADDR" pki_int/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki_int/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki_int/crl"

  log "PKI настроен"
}

# ------------------------------------------------------------------
# Шаг 4: Роли PKI для каждого компонента
# ------------------------------------------------------------------
setup_pki_roles() {
  export VAULT_TOKEN="$ROOT_TOKEN"

  log "Создаём роли PKI..."

  # Роль для Docker daemon (сервер)
  vault write -address="$VAULT_ADDR" pki_int/roles/docker-daemon \
    allowed_domains="docker-daemon,localhost" \
    allow_subdomains=false \
    allow_bare_domains=true \
    allow_localhost=true \
    allow_ip_sans=true \
    max_ttl="720h" \
    key_type="rsa" \
    key_bits=2048

  # Роль для Registry
  vault write -address="$VAULT_ADDR" pki_int/roles/registry \
    allowed_domains="registry,localhost" \
    allow_subdomains=false \
    allow_bare_domains=true \
    allow_localhost=true \
    allow_ip_sans=true \
    max_ttl="720h" \
    key_type="rsa" \
    key_bits=2048

  # Роль для Jenkins (клиентский сертификат для mTLS)
  vault write -address="$VAULT_ADDR" pki_int/roles/jenkins-client \
    allowed_domains="jenkins,jenkins-client" \
    allow_bare_domains=true \
    allow_subdomains=false \
    client_flag=true \
    server_flag=false \
    max_ttl="24h" \
    key_type="rsa" \
    key_bits=2048

  log "Роли PKI созданы"
}

# ------------------------------------------------------------------
# Шаг 5: Выпускаем сертификаты для компонентов
# ------------------------------------------------------------------
issue_certificates() {
  export VAULT_TOKEN="$ROOT_TOKEN"

  log "Выпускаем сертификаты..."

  mkdir -p "$CERTS_DIR/ca" "$CERTS_DIR/registry" "$CERTS_DIR/docker-daemon"

  # Ensure pki_int has a default issuer even when PKI setup is skipped.
  DEFAULT_ISSUER_ID=$(
    vault list -address="$VAULT_ADDR" pki_int/issuers 2>/dev/null | \
    awk '/^----/{getline; if (NF) {print $1; exit}}'
  )
  if [ -n "$DEFAULT_ISSUER_ID" ] && [ "$DEFAULT_ISSUER_ID" != "default" ]; then
    vault write -address="$VAULT_ADDR" pki_int/config/issuers default="$DEFAULT_ISSUER_ID" >/dev/null
  fi
  if [ -z "$DEFAULT_ISSUER_ID" ] || [ "$DEFAULT_ISSUER_ID" = "default" ]; then
    echo "Не найден валидный issuer в pki_int/issuers" >&2
    exit 1
  fi

  # Копируем CA cert
  cp "$CERTS_DIR/ca.crt" "$CERTS_DIR/ca/ca.crt"

  # Сертификат для Docker daemon
  vault write -address="$VAULT_ADDR" -format=json pki_int/issue/docker-daemon \
    issuer_ref="$DEFAULT_ISSUER_ID" \
    common_name="docker-daemon" \
    ip_sans="127.0.0.1" \
    ttl="720h" > /tmp/daemon_cert.json

  echo "$( cat /tmp/daemon_cert.json | grep -o '"certificate":"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n/g' )" \
    > "$CERTS_DIR/docker-daemon/daemon.crt"
  echo "$( cat /tmp/daemon_cert.json | grep -o '"private_key":"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n/g' )" \
    > "$CERTS_DIR/docker-daemon/daemon.key"
  echo "$( cat /tmp/daemon_cert.json | grep -o '"issuing_ca":"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n/g' )" \
    >> "$CERTS_DIR/docker-daemon/daemon.crt"
  chmod 600 "$CERTS_DIR/docker-daemon/daemon.key"

  # Сертификат для Registry
  vault write -address="$VAULT_ADDR" -format=json pki_int/issue/registry \
    issuer_ref="$DEFAULT_ISSUER_ID" \
    common_name="registry" \
    ip_sans="127.0.0.1" \
    ttl="720h" > /tmp/registry_cert.json

  echo "$( cat /tmp/registry_cert.json | grep -o '"certificate":"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n/g' )" \
    > "$CERTS_DIR/registry/registry.crt"
  echo "$( cat /tmp/registry_cert.json | grep -o '"private_key":"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n/g' )" \
    > "$CERTS_DIR/registry/registry.key"
  echo "$( cat /tmp/registry_cert.json | grep -o '"issuing_ca":"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n/g' )" \
    >> "$CERTS_DIR/registry/registry.crt"
  chmod 600 "$CERTS_DIR/registry/registry.key"

  log "Сертификаты выпущены и сохранены в $CERTS_DIR/"
}

# ------------------------------------------------------------------
# Шаг 6: KV для учётных данных registry (bcrypt)
# ------------------------------------------------------------------
setup_registry_secrets() {
  export VAULT_TOKEN="$ROOT_TOKEN"

  if vault secrets list -address="$VAULT_ADDR" | grep -q "^secret/"; then
    log "KV уже включён, пропускаем"
  else
    vault secrets enable -address="$VAULT_ADDR" -path=secret kv-v2
  fi

  READER_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 24)
  WRITER_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 24)

  # Сохраняем пароли в Vault (bcrypt-хэши для htpasswd хранятся в registry/auth)
  vault kv put -address="$VAULT_ADDR" secret/registry/reader \
    username="registry-reader" \
    password="$READER_PASS"

  vault kv put -address="$VAULT_ADDR" secret/registry/writer \
    username="registry-writer" \
    password="$WRITER_PASS"

  # Генерируем htpasswd файл для Registry
  # htpasswd использует bcrypt (-B флаг)
  apk add --no-cache apache2-utils 2>/dev/null || true
  mkdir -p "$REG_AUTH_DIR"
  htpasswd -Bbn "registry-reader" "$READER_PASS" >  "$REG_AUTH_DIR/htpasswd"
  htpasswd -Bbn "registry-writer" "$WRITER_PASS" >> "$REG_AUTH_DIR/htpasswd"

  log "Учётные данные registry сохранены в Vault и htpasswd"
  log "  reader: registry-reader / $READER_PASS"
  log "  writer: registry-writer / $WRITER_PASS"
  echo "$WRITER_PASS" > "$CERTS_DIR/registry_writer_pass.txt"
  echo "$READER_PASS" > "$CERTS_DIR/registry_reader_pass.txt"
}

# ------------------------------------------------------------------
# Шаг 7: Политики доступа
# ------------------------------------------------------------------
setup_policies() {
  export VAULT_TOKEN="$ROOT_TOKEN"

  log "Создаём политики..."

  # Политика для Jenkins: читать клиентский сертификат + секреты writer
  vault policy write -address="$VAULT_ADDR" jenkins-policy - <<'EOF'
# Выпускать клиентский сертификат для Docker mTLS
path "pki_int/issue/jenkins-client" {
  capabilities = ["create", "update"]
}

# Читать учётные данные registry writer
path "secret/data/registry/writer" {
  capabilities = ["read"]
}

# Список
path "secret/metadata/registry/*" {
  capabilities = ["list"]
}
EOF

  # Политика для reader: только читать свои данные
  vault policy write -address="$VAULT_ADDR" registry-reader-policy - <<'EOF'
path "secret/data/registry/reader" {
  capabilities = ["read"]
}
EOF

  log "Политики созданы"
}

# ------------------------------------------------------------------
# Шаг 8: AppRole для Jenkins
# ------------------------------------------------------------------
setup_approle() {
  export VAULT_TOKEN="$ROOT_TOKEN"

  if vault auth list -address="$VAULT_ADDR" | grep -q "approle/"; then
    log "AppRole уже включён, пропускаем"
  else
    vault auth enable -address="$VAULT_ADDR" approle
  fi

  vault write -address="$VAULT_ADDR" auth/approle/role/jenkins \
    token_policies="jenkins-policy" \
    token_ttl="1h" \
    token_max_ttl="4h" \
    secret_id_ttl="720h" \
    secret_id_num_uses=0

  ROLE_ID=$(vault read -address="$VAULT_ADDR" -field=role_id auth/approle/role/jenkins/role-id)
  SECRET_ID=$(vault write -address="$VAULT_ADDR" -force -field=secret_id auth/approle/role/jenkins/secret-id)

  echo "$ROLE_ID"   > "$CERTS_DIR/jenkins_role_id.txt"
  echo "$SECRET_ID" > "$CERTS_DIR/jenkins_secret_id.txt"
  chmod 600 "$CERTS_DIR/jenkins_role_id.txt" "$CERTS_DIR/jenkins_secret_id.txt"

  log "AppRole Jenkins создан"
  log "  VAULT_ROLE_ID:   $ROLE_ID"
  log "  VAULT_SECRET_ID: $SECRET_ID"
}

# ------------------------------------------------------------------
# Шаг 9: Отзываем root-токен
# ------------------------------------------------------------------
revoke_root_token() {
  log "Отзываем root-токен..."
  vault token revoke -address="$VAULT_ADDR" -self || true
  # Удаляем из файла (сохраняем только для экстренного случая - закомментировать в проде)
  # rm -f "$CERTS_DIR/root_token.txt"
  log "Root-токен отозван. Дальнейшая работа — только через AppRole."
}

# ------------------------------------------------------------------
# Главный поток
# ------------------------------------------------------------------
main() {
  wait_vault
  init_vault
  unseal_vault
  setup_pki
  setup_pki_roles
  issue_certificates
  setup_registry_secrets
  setup_policies
  setup_approle
  revoke_root_token

  log ""
  log "=============================================="
  log "  Vault инициализирован и настроен!"
  log "  Ключи unseal: $CERTS_DIR/unseal_key_[1-3].txt"
  log "  AppRole creds: $CERTS_DIR/jenkins_*.txt"
  log "  Сертификаты:   $CERTS_DIR/{ca,registry,docker-daemon}/"
  log "=============================================="
}

main
