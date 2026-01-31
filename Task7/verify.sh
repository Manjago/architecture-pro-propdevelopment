#!/bin/bash

echo "🚀 Настройка Namespace с PSA (Pod Security Admission)..."
kubectl apply -f Task7/01-create-namespace.yaml

echo "🛑 Тест 1: Попытка создания Privileged Pod (Должно быть запрещено)..."
if ! kubectl apply -f Task7/insecure-manifests/01-privileged.yaml 2>&1 | grep "Forbidden"; then
    echo "❌ Ошибка: Privileged Pod был создан, хотя должен быть заблокирован!"
else
    echo "✅ Успех: Privileged Pod заблокирован."
fi

echo "🛑 Тест 2: Попытка создания Root User Pod (Должно быть запрещено)..."
if ! kubectl apply -f Task7/insecure-manifests/02-root-user.yaml 2>&1 | grep "Forbidden"; then
    echo "❌ Ошибка: Root Pod был создан, хотя должен быть заблокирован!"
else
    echo "✅ Успех: Root Pod заблокирован."
fi

echo "🟢 Тест 3: Создание Secure Pod (Должно быть разрешено)..."
if kubectl apply -f Task7/secure-manifests/01-secure.yaml; then
    echo "✅ Успех: Secure Pod создан."
else
    echo "❌ Ошибка: Secure Pod не создался!"
fi

echo "📊 Итоговый статус подов в audit-zone:"
kubectl get pods -n audit-zone
