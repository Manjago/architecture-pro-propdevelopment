#!/bin/bash

echo "😈 Запуск симуляции атаки..."

# 1. Создаем namespace и service account
kubectl create ns secure-ops
kubectl create sa monitoring -n secure-ops

# 2. Создаем "злой" под (эмуляция хакера)
echo "🚀 Запуск attacker-pod..."
kubectl run attacker-pod --image=alpine --command -- sleep 3600 -n secure-ops

# 3. Попытка чтения секретов (должно быть запрещено, но мы это залогируем)
echo "🕵️ Попытка чтения секретов..."
kubectl auth can-i get secrets --as=system:serviceaccount:secure-ops:monitoring -n kube-system

# 4. Попытка создания привилегированного пода (Privileged Pod)
echo "💣 Попытка создания Privileged Pod..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: secure-ops
spec:
  containers:
  - name: pwn
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
EOF

# 5. "Случайное" удаление политики (эмуляция)
# В реальности мы не можем удалить файл внутри API сервера через kubectl,
# но мы сделаем действие, которое оставит след.
kubectl delete configmap -n kube-system extension-apiserver-authentication --ignore-not-found

echo "✅ Симуляция завершена. Ждем сброса логов на диск..."
sleep 5
