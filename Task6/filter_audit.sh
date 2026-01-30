#!/bin/bash
# filter_audit.sh - Bash скрипт для фильтрации Kubernetes audit.log
# Использует jq для парсинга JSON

AUDIT_LOG="${1:-audit.log}"
OUTPUT_FILE="audit-extract.json"

if [ ! -f "$AUDIT_LOG" ]; then
    echo "❌ Файл $AUDIT_LOG не найден"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "❌ jq не установлен. Установите: sudo apt install jq"
    exit 1
fi

echo "🔍 Kubernetes Audit Log Analyzer (Bash version)"
echo "=============================================="
echo "📂 Анализ файла: $AUDIT_LOG"
echo ""

# Временный файл для сбора результатов
TEMP_FILE=$(mktemp)

echo "[" > "$TEMP_FILE"
first=true

# 1. Поиск privileged pods
echo "🔍 Поиск privileged pods..."
while IFS= read -r line; do
    if [ "$first" = true ]; then
        first=false
    else
        echo "," >> "$TEMP_FILE"
    fi
    
    timestamp=$(echo "$line" | jq -r '.stageTimestamp // .requestReceivedTimestamp')
    user=$(echo "$line" | jq -r '.user.username')
    pod_name=$(echo "$line" | jq -r '.objectRef.name')
    namespace=$(echo "$line" | jq -r '.objectRef.namespace')
    
    cat >> "$TEMP_FILE" << EOF
  {
    "alert_type": "PRIVILEGED_POD_CREATION",
    "severity": "CRITICAL",
    "description": "Создание pod с privileged: true позволяет выход из контейнера на хост",
    "timestamp": "$timestamp",
    "user": "$user",
    "namespace": "$namespace",
    "name": "$pod_name"
  }
EOF
done < <(jq -c 'select(.verb == "create" and .objectRef.resource == "pods" and .requestObject.spec.containers[].securityContext.privileged == true)' "$AUDIT_LOG" 2>/dev/null)

# 2. Поиск forbidden secret access
echo "🔍 Поиск попыток доступа к секретам (403)..."
while IFS= read -r line; do
    if [ "$first" = true ]; then
        first=false
    else
        echo "," >> "$TEMP_FILE"
    fi
    
    timestamp=$(echo "$line" | jq -r '.stageTimestamp // .requestReceivedTimestamp')
    user=$(echo "$line" | jq -r '.user.username')
    namespace=$(echo "$line" | jq -r '.objectRef.namespace')
    secret_name=$(echo "$line" | jq -r '.objectRef.name // "all"')
    
    cat >> "$TEMP_FILE" << EOF
  {
    "alert_type": "FORBIDDEN_SECRET_ACCESS",
    "severity": "HIGH",
    "description": "Попытка доступа к секретам без разрешения",
    "timestamp": "$timestamp",
    "user": "$user",
    "namespace": "$namespace",
    "name": "$secret_name"
  }
EOF
done < <(jq -c 'select(.objectRef.resource == "secrets" and .responseStatus.code == 403)' "$AUDIT_LOG" 2>/dev/null)

# 3. Поиск kubectl exec
echo "🔍 Поиск exec в поды..."
while IFS= read -r line; do
    if [ "$first" = true ]; then
        first=false
    else
        echo "," >> "$TEMP_FILE"
    fi
    
    timestamp=$(echo "$line" | jq -r '.stageTimestamp // .requestReceivedTimestamp')
    user=$(echo "$line" | jq -r '.user.username')
    namespace=$(echo "$line" | jq -r '.objectRef.namespace')
    pod_name=$(echo "$line" | jq -r '.objectRef.name')
    
    severity="MEDIUM"
    if [ "$namespace" = "kube-system" ]; then
        severity="HIGH"
    fi
    
    cat >> "$TEMP_FILE" << EOF
  {
    "alert_type": "POD_EXEC",
    "severity": "$severity",
    "description": "Exec в pod namespace: $namespace",
    "timestamp": "$timestamp",
    "user": "$user",
    "namespace": "$namespace",
    "name": "$pod_name"
  }
EOF
done < <(jq -c 'select(.verb == "create" and .objectRef.subresource == "exec")' "$AUDIT_LOG" 2>/dev/null)

# 4. Поиск RoleBinding с cluster-admin
echo "🔍 Поиск эскалации привилегий (cluster-admin)..."
while IFS= read -r line; do
    if [ "$first" = true ]; then
        first=false
    else
        echo "," >> "$TEMP_FILE"
    fi
    
    timestamp=$(echo "$line" | jq -r '.stageTimestamp // .requestReceivedTimestamp')
    user=$(echo "$line" | jq -r '.user.username')
    namespace=$(echo "$line" | jq -r '.objectRef.namespace')
    binding_name=$(echo "$line" | jq -r '.objectRef.name')
    
    cat >> "$TEMP_FILE" << EOF
  {
    "alert_type": "PRIVILEGE_ESCALATION",
    "severity": "CRITICAL",
    "description": "Создание RoleBinding с cluster-admin - эскалация привилегий!",
    "timestamp": "$timestamp",
    "user": "$user",
    "namespace": "$namespace",
    "name": "$binding_name"
  }
EOF
done < <(jq -c 'select(.verb == "create" and (.objectRef.resource == "rolebindings" or .objectRef.resource == "clusterrolebindings") and .requestObject.roleRef.name == "cluster-admin")' "$AUDIT_LOG" 2>/dev/null)

# 5. Поиск изменений в kube-system
echo "🔍 Поиск модификаций в kube-system..."
while IFS= read -r line; do
    if [ "$first" = true ]; then
        first=false
    else
        echo "," >> "$TEMP_FILE"
    fi
    
    timestamp=$(echo "$line" | jq -r '.stageTimestamp // .requestReceivedTimestamp')
    user=$(echo "$line" | jq -r '.user.username')
    verb=$(echo "$line" | jq -r '.verb')
    resource=$(echo "$line" | jq -r '.objectRef.resource')
    name=$(echo "$line" | jq -r '.objectRef.name')
    
    cat >> "$TEMP_FILE" << EOF
  {
    "alert_type": "KUBE_SYSTEM_MODIFICATION",
    "severity": "HIGH",
    "description": "Модификация ($verb) ресурса $resource в kube-system",
    "timestamp": "$timestamp",
    "user": "$user",
    "namespace": "kube-system",
    "name": "$name"
  }
EOF
done < <(jq -c 'select((.verb == "create" or .verb == "delete" or .verb == "update" or .verb == "patch") and .objectRef.namespace == "kube-system" and .objectRef.resource != "events" and .objectRef.resource != "pods")' "$AUDIT_LOG" 2>/dev/null)

echo "]" >> "$TEMP_FILE"

# Убираем лишние запятые и форматируем
jq '.' "$TEMP_FILE" > "$OUTPUT_FILE" 2>/dev/null || cp "$TEMP_FILE" "$OUTPUT_FILE"
rm -f "$TEMP_FILE"

# Подсчёт результатов
total=$(jq 'length' "$OUTPUT_FILE")
critical=$(jq '[.[] | select(.severity == "CRITICAL")] | length' "$OUTPUT_FILE")
high=$(jq '[.[] | select(.severity == "HIGH")] | length' "$OUTPUT_FILE")

echo ""
echo "=============================================="
echo "📊 РЕЗУЛЬТАТЫ АНАЛИЗА"
echo "=============================================="
echo "🚨 Всего подозрительных событий: $total"
echo "  🔴 CRITICAL: $critical"
echo "  🟠 HIGH: $high"
echo ""
echo "💾 Результаты сохранены в $OUTPUT_FILE"
echo ""

if [ "$critical" -gt 0 ]; then
    echo "⚠️  Обнаружено $critical критических событий!"
    exit 1
fi

exit 0
