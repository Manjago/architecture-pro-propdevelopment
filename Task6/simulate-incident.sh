#!/bin/bash
# simulate-incident.sh
# Скрипт симуляции подозрительной активности в Kubernetes кластере
# Для Task 6: Аудит активности пользователей и обнаружение инцидентов

set -e

echo "😈 Запуск симуляции атаки..."
echo "============================================"

# 1. Создаём namespace и service account
echo "[1/6] Создание namespace и service account..."
kubectl create ns secure-ops 2>/dev/null || echo "Namespace уже существует"
kubectl config set-context --current --namespace=secure-ops
kubectl create sa monitoring 2>/dev/null || echo "ServiceAccount уже существует"

# 2. Создаём обычный под (эмуляция присутствия атакующего)
echo "[2/6] Запуск attacker-pod..."
kubectl run attacker-pod --image=alpine --command -- sleep 3600 2>/dev/null || echo "Pod уже существует"

# 3. Попытка чтения секретов от имени service account (проверка прав)
echo "[3/6] 🕵️ Попытка чтения секретов из kube-system..."
kubectl auth can-i get secrets --as=system:serviceaccount:secure-ops:monitoring -n kube-system || true

# Попытка реально прочитать секрет (должна быть отклонена)
kubectl get secret -n kube-system --as=system:serviceaccount:secure-ops:monitoring 2>&1 || true

# 4. Создание привилегированного пода (Privileged Pod) - ОПАСНО!
echo "[4/6] 💣 Попытка создания Privileged Pod..."
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
  restartPolicy: Never
EOF

# 5. Попытка exec в системный под (CoreDNS)
echo "[5/6] 🔓 Попытка exec в системный под..."
COREDNS_POD=$(kubectl get pods -n kube-system -l k8s-app=kube-dns -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -n "$COREDNS_POD" ]; then
    kubectl exec -n kube-system "$COREDNS_POD" -- cat /etc/resolv.conf 2>&1 || true
else
    echo "CoreDNS pod не найден, пропускаем..."
fi

# 6. Создание RoleBinding с правами cluster-admin (эскалация привилегий!)
echo "[6/6] 🚨 Создание RoleBinding с cluster-admin..."
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: escalate-binding
  namespace: secure-ops
subjects:
- kind: ServiceAccount
  name: monitoring
  namespace: secure-ops
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

echo "============================================"
echo "✅ Симуляция завершена!"
echo ""
echo "Подозрительные действия, которые должны быть в audit.log:"
echo "  1. Создание namespace secure-ops"
echo "  2. Создание ServiceAccount monitoring"
echo "  3. Попытка доступа к секретам (Forbidden)"
echo "  4. Создание privileged pod"
echo "  5. Exec в системный под kube-system"
echo "  6. Создание RoleBinding с cluster-admin (эскалация привилегий)"
echo ""
echo "Для анализа логов выполните:"
echo "  minikube ssh -- sudo cat /var/log/kubernetes/audit/audit.log > audit.log"
echo "  python3 filter_audit.py"
