#!/bin/bash

# Создаем папку для сертификатов, если нет
mkdir -p .certs

# Функция создания пользователя
create_user() {
    USER=$1
    GROUP=$2
    echo "--- Создаем пользователя: $USER (Group: $GROUP) ---"

    # 1. Генерируем приватный ключ
    openssl genrsa -out .certs/$USER.key 2048

    # 2. Генерируем CSR (Certificate Signing Request)
    # Важно: CN=user, O=group
    openssl req -new -key .certs/$USER.key -out .certs/$USER.csr -subj "/CN=$USER/O=$GROUP"

    # 3. Подписываем сертификат CA-ключом Minikube
    # Путь к CA может отличаться, проверяем стандартный ~/.minikube
    CA_CRT=~/.minikube/ca.crt
    CA_KEY=~/.minikube/ca.key

    openssl x509 -req -in .certs/$USER.csr -CA $CA_CRT -CAkey $CA_KEY -CAcreateserial -out .certs/$USER.crt -days 500

    # 4. Добавляем пользователя в kubeconfig
    kubectl config set-credentials $USER --client-certificate=.certs/$USER.crt --client-key=.certs/$USER.key
    
    # 5. Создаем контекст (для удобства переключения)
    kubectl config set-context $USER-context --cluster=minikube --user=$USER
    
    echo "✅ Пользователь $USER создан и добавлен в kubeconfig"
    echo ""
}

# Создаем двух пользователей согласно заданию
# 1. Разработчик (только просмотр)
create_user "dev-user" "developers"

# 2. Аудитор безопасности (просмотр секретов)
create_user "audit-user" "security-audit"

# 3. Админ неймспейса
create_user "po-user" "product-owner"
