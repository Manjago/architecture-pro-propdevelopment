#!/usr/bin/env python3
"""
filter_audit.py - Скрипт фильтрации Kubernetes audit.log для выявления подозрительных событий

Использование:
    python3 filter_audit.py [путь_к_audit.log]

Если путь не указан, используется audit.log в текущей директории.
"""

import json
import sys
from datetime import datetime
from typing import List, Dict, Any

# Файлы по умолчанию
DEFAULT_INPUT = "audit.log"
OUTPUT_FILE = "audit-extract.json"


def load_audit_log(filepath: str) -> List[Dict[str, Any]]:
    """Загружает audit.log (JSON Lines формат)"""
    events = []
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    events.append(event)
                except json.JSONDecodeError as e:
                    print(f"⚠️  Ошибка парсинга строки {line_num}: {e}")
    except FileNotFoundError:
        print(f"❌ Файл {filepath} не найден")
        sys.exit(1)
    
    print(f"📂 Загружено {len(events)} событий из {filepath}")
    return events


def is_privileged_pod(event: Dict) -> bool:
    """Проверяет, является ли событие созданием privileged pod"""
    if event.get('verb') != 'create':
        return False
    
    obj_ref = event.get('objectRef', {})
    if obj_ref.get('resource') != 'pods':
        return False
    
    request_obj = event.get('requestObject', {})
    containers = request_obj.get('spec', {}).get('containers', [])
    
    for container in containers:
        sec_context = container.get('securityContext', {})
        if sec_context.get('privileged') is True:
            return True
    
    return False


def is_forbidden_secret_access(event: Dict) -> bool:
    """Проверяет, является ли событие запрещённым доступом к секретам"""
    obj_ref = event.get('objectRef', {})
    if obj_ref.get('resource') != 'secrets':
        return False
    
    response = event.get('responseStatus', {})
    if response.get('code') == 403:
        return True
    
    return False


def is_exec_in_pod(event: Dict) -> bool:
    """Проверяет, является ли событие exec в под"""
    obj_ref = event.get('objectRef', {})
    if obj_ref.get('subresource') == 'exec':
        return True
    
    # Альтернативная проверка по URI
    uri = event.get('requestURI', '')
    if '/exec' in uri:
        return True
    
    return False


def is_cluster_admin_binding(event: Dict) -> bool:
    """Проверяет, является ли событие созданием RoleBinding с cluster-admin"""
    if event.get('verb') != 'create':
        return False
    
    obj_ref = event.get('objectRef', {})
    if obj_ref.get('resource') not in ['rolebindings', 'clusterrolebindings']:
        return False
    
    request_obj = event.get('requestObject', {})
    role_ref = request_obj.get('roleRef', {})
    
    if role_ref.get('name') == 'cluster-admin':
        return True
    
    return False


def is_kube_system_modification(event: Dict) -> bool:
    """Проверяет, является ли событие модификацией ресурсов в kube-system"""
    if event.get('verb') not in ['create', 'delete', 'update', 'patch']:
        return False
    
    obj_ref = event.get('objectRef', {})
    if obj_ref.get('namespace') == 'kube-system':
        return True
    
    return False


def analyze_events(events: List[Dict]) -> List[Dict]:
    """Анализирует события и возвращает подозрительные"""
    suspicious = []
    
    for event in events:
        alert_type = None
        severity = "MEDIUM"
        description = ""
        
        # 1. Privileged Pod
        if is_privileged_pod(event):
            alert_type = "PRIVILEGED_POD_CREATION"
            severity = "CRITICAL"
            description = "Создание pod с privileged: true позволяет выход из контейнера на хост"
        
        # 2. Forbidden Secret Access
        elif is_forbidden_secret_access(event):
            alert_type = "FORBIDDEN_SECRET_ACCESS"
            severity = "HIGH"
            description = "Попытка доступа к секретам без разрешения - возможная разведка"
        
        # 3. Exec in Pod
        elif is_exec_in_pod(event):
            alert_type = "POD_EXEC"
            severity = "MEDIUM"
            namespace = event.get('objectRef', {}).get('namespace', 'unknown')
            if namespace == 'kube-system':
                severity = "HIGH"
                description = "Exec в системный pod kube-system - возможная компрометация"
            else:
                description = "Exec в pod - требует проверки легитимности"
        
        # 4. Cluster Admin Binding
        elif is_cluster_admin_binding(event):
            alert_type = "PRIVILEGE_ESCALATION"
            severity = "CRITICAL"
            description = "Создание RoleBinding с cluster-admin - эскалация привилегий!"
        
        # 5. Kube-system Modification
        elif is_kube_system_modification(event):
            alert_type = "KUBE_SYSTEM_MODIFICATION"
            severity = "HIGH"
            verb = event.get('verb', 'unknown')
            resource = event.get('objectRef', {}).get('resource', 'unknown')
            description = f"Модификация ({verb}) ресурса {resource} в kube-system"
        
        if alert_type:
            suspicious.append({
                "alert_type": alert_type,
                "severity": severity,
                "description": description,
                "timestamp": event.get('stageTimestamp') or event.get('requestReceivedTimestamp'),
                "user": event.get('user', {}).get('username', 'unknown'),
                "source_ip": event.get('sourceIPs', ['unknown'])[0] if event.get('sourceIPs') else 'unknown',
                "verb": event.get('verb'),
                "resource": event.get('objectRef', {}).get('resource'),
                "namespace": event.get('objectRef', {}).get('namespace'),
                "name": event.get('objectRef', {}).get('name'),
                "response_code": event.get('responseStatus', {}).get('code'),
                "audit_id": event.get('auditID'),
                "raw_event": event  # Сохраняем полное событие для детального анализа
            })
    
    return suspicious


def print_summary(suspicious: List[Dict]):
    """Выводит краткую сводку по найденным событиям"""
    print("\n" + "="*60)
    print("📊 РЕЗУЛЬТАТЫ АНАЛИЗА AUDIT LOG")
    print("="*60)
    
    if not suspicious:
        print("✅ Подозрительных событий не обнаружено")
        return
    
    # Группировка по типу
    by_type = {}
    for s in suspicious:
        t = s['alert_type']
        by_type[t] = by_type.get(t, 0) + 1
    
    # Группировка по severity
    by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for s in suspicious:
        sev = s['severity']
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    print(f"\n🚨 Всего подозрительных событий: {len(suspicious)}")
    
    print("\n📈 По уровню критичности:")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = by_severity.get(sev, 0)
        if count > 0:
            emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}[sev]
            print(f"  {emoji} {sev}: {count}")
    
    print("\n📋 По типу события:")
    for alert_type, count in sorted(by_type.items()):
        print(f"  • {alert_type}: {count}")
    
    print("\n🔍 Детали критических событий:")
    for s in suspicious:
        if s['severity'] in ['CRITICAL', 'HIGH']:
            print(f"\n  [{s['severity']}] {s['alert_type']}")
            print(f"    Время: {s['timestamp']}")
            print(f"    Пользователь: {s['user']}")
            print(f"    Действие: {s['verb']} {s['resource']}/{s['name']}")
            print(f"    Namespace: {s['namespace']}")
            print(f"    Описание: {s['description']}")


def save_results(suspicious: List[Dict], output_file: str):
    """Сохраняет результаты в JSON файл"""
    # Убираем raw_event для компактности выходного файла
    output = []
    for s in suspicious:
        item = {k: v for k, v in s.items() if k != 'raw_event'}
        output.append(item)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Результаты сохранены в {output_file}")


def main():
    # Определяем входной файл
    input_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT
    
    print("🔍 Kubernetes Audit Log Analyzer")
    print("="*60)
    
    # Загружаем и анализируем
    events = load_audit_log(input_file)
    suspicious = analyze_events(events)
    
    # Выводим результаты
    print_summary(suspicious)
    
    # Сохраняем
    save_results(suspicious, OUTPUT_FILE)
    
    print("\n" + "="*60)
    print("✅ Анализ завершён")
    
    # Возвращаем код в зависимости от наличия критических событий
    critical_count = sum(1 for s in suspicious if s['severity'] == 'CRITICAL')
    if critical_count > 0:
        print(f"⚠️  Обнаружено {critical_count} критических событий!")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
