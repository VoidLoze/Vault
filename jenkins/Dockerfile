FROM jenkins/jenkins:lts-jdk21

USER root

# Устанавливаем Docker CLI и утилиты
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    gnupg \
    jq \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем Vault CLI
RUN curl -fsSL https://releases.hashicorp.com/vault/1.17.0/vault_1.17.0_linux_arm64.zip -o /tmp/vault.zip \
    && unzip /tmp/vault.zip -d /usr/local/bin/ \
    && rm /tmp/vault.zip \
    && chmod +x /usr/local/bin/vault

# Устанавливаем плагины от root с явным указанием директории
RUN jenkins-plugin-cli -d /usr/share/jenkins/ref/plugins --plugins \
    configuration-as-code \
    hashicorp-vault-plugin \
    docker-workflow \
    workflow-aggregator \
    git \
    credentials \
    credentials-binding \
    timestamper \
    ws-cleanup \
    ansicolor 

USER jenkins
