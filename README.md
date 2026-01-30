# Проектная работа: Архитектура безопасности PropDevelopment

## 📋 Описание проекта
В данном репозитории содержится комплексное проектное решение по обеспечению информационной безопасности для компании **PropDevelopment** (Спринт 5).
Компания занимается девелопментом и управлением недвижимостью, внедряет сервисы "Умный дом" и имеет сложную экосистему партнеров.

**Цели проекта:**
1.  Обеспечить соответствие законодательству РФ (152-ФЗ).
2.  Защитить данные клиентов и собственников от утечек.
3.  Обеспечить безопасную интеграцию с внешними партнерами (УК, IoT).
4.  Внедрить практики DevSecOps в Kubernetes.

---

## 🗂 Структура решения

### ✅ [Task 1] Модель угроз и классификация данных
Анализ типов данных, циркулирующих в системе, и визуализация векторов атак.
*   📄 **[Mindmap: Классификация данных и риски](./Task1/data_security.png)** — визуальная карта активов и угроз.
*   ℹ️ *Исходный код:* [data_security.puml](./Task1/data_security.puml) (PlantUML).

### ✅ [Task 2] Проверочный лист (Security Checklist)
Аудит текущего состояния безопасности и выявление критических дефицитов.
*   📄 **[Чек-лист аудита ИБ](./Task2/checklist.md)** — детальный анализ по доменам (Доступ, Данные, Инфраструктура, API, IoT).
*   **Результат:** Выявлены критические проблемы с изоляцией данных партнеров (Tenant Isolation) и отсутствием единой политики API.

### ✅ [Task 3] Безопасные внешние интеграции
Проектирование архитектуры взаимодействия с "Умным домом" и партнерами.
*   📐 **[C4 Context](./Task3/c1_context.png)** — схема интеграции с IoT-устройствами и облаком партнера.
*   📦 **[C4 Container](./Task3/c2_container.png)** — детализация потоков данных через API Gateway и IoT Adapter.
*   📝 **[Требования к интеграции](./Task3/integration_requirements.md)** — описание протоколов (mTLS, OIDC) и мер безопасности.
*   ℹ️ *Исходный код:* [c1_context.puml](./Task3/c1_context.puml), [c2_container.puml](./Task3/c2_container.puml).

### ✅ [Task 4] Защита доступа к кластеру (RBAC)
Настройка ролевой модели доступа для различных групп пользователей в Kubernetes.
*   📄 **[Таблица ролей](./Task4/rbac_roles.md)** — описание ролей и полномочий.
*   ⚙️ **Артефакты:**
    *   `create_users.sh` — скрипт для генерации сертификатов пользователей.
    *   `create_roles.yaml` — манифест с `Role` и `ClusterRole`.
    *   `create_bindings.yaml` — манифест с `RoleBinding` и `ClusterRoleBinding`.
*   **Для проверки:**
    ```bash
    ./Task4/create_users.sh
    kubectl apply -f Task4/create_roles.yaml
    kubectl apply -f Task4/create_bindings.yaml
    
    # Разрешено
    kubectl auth can-i list pods --as=dev-user --as-group=developers
    
    # Запрещено
    kubectl auth can-i get secrets --as=dev-user --as-group=developers
    ```

### ✅ [Task 5] Управление трафиком (Network Policies)
Микросегментация трафика между сервисами для изоляции контуров (Public vs Admin).

*   ⚙️ **Артефакты:**
    *   `deploy_pods.sh` — скрипт для развертывания тестовых сервисов (front-end, back-end, admin).
    *   `network_policies.yaml` — манифесты `NetworkPolicy` (Default Deny + Allow rules).

*   ⚠️ **Важно для проверки:**
    Стандартный драйвер Minikube (`bridge`) не поддерживает NetworkPolicy. Для корректной работы требуется CNI плагин (например, Calico).
    
    **Запуск кластера с поддержкой Network Policies:**
    ```bash
    minikube start --network-plugin=cni --cni=calico --driver=docker
    ```

*   **Сценарий проверки:**
    ```bash
    ./Task5/deploy_pods.sh
    kubectl apply -f Task5/network_policies.yaml
    
    # 1. Разрешено (front -> back) -> Должен вернуть HTML
    kubectl exec -n net-test front-end -- curl -s -m 2 back-end-api
    
    # 2. Запрещено (front -> admin-back) -> Должен быть TIMEOUT (exit code 28)
    kubectl exec -n net-test front-end -- curl -s -m 2 admin-back-end-api
    
    # 3. Разрешено (admin-front -> admin-back) -> Должен вернуть HTML
    kubectl exec -n net-test admin-front-end -- curl -s -m 2 admin-back-end-api
    ```
    
### ✅ [Task 6] Аудит активности пользователей и обнаружение инцидентов

## Описание решения

### Проблема с Minikube

При выполнении задания столкнулся с известной проблемой Minikube (Docker driver) — API Server не стартует при включении Audit Logging:

```
[control-plane-check] kube-apiserver is not healthy after 4m0.001085691s
```

**Причина:** В Minikube с Docker driver файловая система внутри контейнера имеет ограничения на запись. API Server не может создать файл `audit.log` в указанном пути, что приводит к его падению при старте.

**Попытки решения:**
1. `--mount` с разными путями (`/var/log/`, `/var/lib/minikube/`)
2. Использование `~/.minikube/files/` для автоматического копирования
3. Изменение путей audit-log-path

Ни один из вариантов не привёл к успеху — это [известная issue](https://github.com/kubernetes/minikube/issues) в сочетании Minikube + Docker driver + Audit.

### Принятое решение

Для демонстрации понимания процесса аудита и анализа безопасности был создан **реалистичный пример audit.log** на основе событий, которые бы сгенерировал скрипт симуляции атаки.

---

## Структура файлов

```
Task6/
├── audit-policy.yaml         # Политика аудита для Kubernetes
├── simulate-incident.sh      # Скрипт симуляции атаки
├── audit.log                 # Пример audit log (JSON Lines)
├── filter_audit.py           # Скрипт фильтрации на Python
├── audit-extract.json        # Выжимка подозрительных событий
└── analysis.md               # Отчёт по результатам анализа
```

---

## Как проверить работу скрипта

```bash
cd Task6

# Запуск анализатора
python3 filter_audit.py audit.log

# Результат будет в audit-extract.json
cat audit-extract.json
```

---

## Содержание отчёта (analysis.md)

Отчёт содержит анализ следующих событий:

| № | Событие | Severity | Описание |
|---|---------|----------|----------|
| 1 | FORBIDDEN_SECRET_ACCESS | HIGH | SA пытается читать секреты kube-system |
| 2 | PRIVILEGED_POD_CREATION | CRITICAL | Создание pod с privileged: true |
| 3 | POD_EXEC | HIGH | Exec в системный pod CoreDNS |
| 4 | PRIVILEGE_ESCALATION | CRITICAL | RoleBinding с cluster-admin |
| 5 | KUBE_SYSTEM_MODIFICATION | HIGH | Удаление ConfigMap в kube-system |

---

## Ключевые выводы

1. **Цепочка атаки:** Разведка → Privileged Pod → Lateral Movement → Privilege Escalation
2. **Ошибки RBAC:** Отсутствие PodSecurityAdmission, слишком широкие права пользователя
3. **Рекомендации:** Включить PSA (restricted), внедрить OPA Gatekeeper, настроить namespace isolation

---

## Примечание для ревьюера

Если необходимо проверить работу в реальном Kubernetes кластере с Audit Logging:

1. Использовать **kind** вместо minikube (поддерживает audit из коробки)
2. Использовать **managed Kubernetes** (GKE, EKS, AKS)
3. Использовать **minikube с driver=kvm2** (не docker)

Пример для kind:
```bash
kind create cluster --config kind-with-audit.yaml
```

Спасибо за понимание! 🙏


### ⏳ [Task 7] Расследование инцидентов и Security Policies (В ожидании)
Настройка аудита, анализ логов и применение политик безопасности (OPA Gatekeeper).

---
*Автор: Кирилл Темненков*
*Курс: Архитектура ПО: продвинутый уровень*
