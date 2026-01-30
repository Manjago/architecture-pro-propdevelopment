import json

LOG_FILE = "Task6/logs/audit.log"
OUTPUT_FILE = "Task6/audit-extract.json"

suspicious_events = []

print(f"🔍 Анализ файла {LOG_FILE}...")

try:
    with open(LOG_FILE, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                
                # 1. Поиск Privileged Pods
                if entry.get('verb') == 'create' and entry.get('objectRef', {}).get('resource') == 'pods':
                    request_obj = entry.get('requestObject', {})
                    containers = request_obj.get('spec', {}).get('containers', [])
                    for c in containers:
                        if c.get('securityContext', {}).get('privileged'):
                            suspicious_events.append({
                                "alert": "Privileged Pod Creation",
                                "user": entry.get('user', {}).get('username'),
                                "pod_name": entry.get('objectRef', {}).get('name'),
                                "timestamp": entry.get('stageTimestamp')
                            })

                # 2. Попытка доступа к секретам (Forbidden)
                if entry.get('verb') == 'get' and entry.get('objectRef', {}).get('resource') == 'secrets':
                    if entry.get('responseStatus', {}).get('code') == 403:
                         suspicious_events.append({
                                "alert": "Forbidden Secret Access",
                                "user": entry.get('user', {}).get('username'),
                                "timestamp": entry.get('stageTimestamp')
                            })

            except json.JSONDecodeError:
                continue
except FileNotFoundError:
    print("❌ Файл audit.log не найден. Сначала запустите симуляцию и скопируйте лог.")
    exit(1)

# Сохраняем результат
with open(OUTPUT_FILE, 'w') as f:
    json.dump(suspicious_events, f, indent=2)

print(f"✅ Анализ завершен. Найдено {len(suspicious_events)} подозрительных событий.")
print(f"📄 Результат сохранен в {OUTPUT_FILE}")