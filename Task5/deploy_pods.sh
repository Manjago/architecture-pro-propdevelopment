#!/bin/bash

# Создаем namespace
kubectl create ns net-test

# Функция запуска пода
run_pod() {
    NAME=$1
    ROLE=$2
    # --restart=Never чтобы создать именно Pod, а не Deployment (для простоты теста)
    kubectl run $NAME --image=nginx --labels="role=$ROLE,app=$NAME" --port=80 -n net-test --restart=Never
    kubectl expose pod $NAME --port=80 -n net-test
}

echo "🚀 Deploying pods..."

# 1. Публичный контур
run_pod "front-end" "front-end"
run_pod "back-end-api" "back-end-api"

# 2. Админский контур
run_pod "admin-front-end" "admin-front-end"
run_pod "admin-back-end-api" "admin-back-end-api"

echo "⏳ Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod --all -n net-test --timeout=120s
