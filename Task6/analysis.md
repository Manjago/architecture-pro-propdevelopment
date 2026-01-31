# Отчёт по результатам анализа Kubernetes Audit Log

**Дата анализа:** 2026-01-30  
**Аналитик:** [Ваше имя]  
**Кластер:** minikube (PropDevelopment test environment)

---

## Резюме

В ходе анализа Kubernetes audit log выявлено **6 подозрительных событий**, из которых:
- 🔴 **2 критических** (CRITICAL)
- 🟠 **4 высокой степени** (HIGH)

Выявленные события указывают на **симуляцию атаки с эскалацией привилегий** — типичный сценарий компрометации Kubernetes кластера.

---

## Подозрительные события

### 1. Доступ к секретам (Forbidden)

| Параметр | Значение |
|----------|----------|
| **Тип** | FORBIDDEN_SECRET_ACCESS |
| **Severity** | HIGH |
| **Кто** | `system:serviceaccount:secure-ops:monitoring` |
| **Где** | namespace: `kube-system` |
| **Когда** | 2026-01-30T18:00:04Z, 2026-01-30T18:00:05Z |

**Описание:**  
ServiceAccount `monitoring` из namespace `secure-ops` дважды пытался получить доступ к секретам в системном namespace `kube-system`:
1. Попытка листинга всех секретов (`list secrets`)
2. Попытка чтения конкретного секрета `default-token-abc123`

Обе попытки были **отклонены** (HTTP 403 Forbidden), что говорит о корректной работе RBAC.

**Почему подозрительно:**  
- ServiceAccount из пользовательского namespace не должен пытаться читать секреты из `kube-system`
- Это типичное поведение при **разведке** (reconnaissance) — атакующий проверяет, к чему у него есть доступ
- Повторяющиеся запросы указывают на автоматизированный скрипт или инструмент

**Рекомендации:**
- Проверить, кто и зачем создал ServiceAccount `monitoring`
- Добавить NetworkPolicy для ограничения исходящего трафика из namespace `secure-ops`
- Настроить алерты в SIEM на события `403 Forbidden` для доступа к secrets

---

### 2. Привилегированные поды

| Параметр | Значение |
|----------|----------|
| **Тип** | PRIVILEGED_POD_CREATION |
| **Severity** | 🔴 CRITICAL |
| **Кто** | `minikube-user` |
| **Где** | namespace: `secure-ops`, pod: `privileged-pod` |
| **Когда** | 2026-01-30T18:00:06Z |

**Описание:**  
Пользователь `minikube-user` создал pod с флагом `securityContext.privileged: true`.

**Почему подозрительно:**  
- Privileged pod имеет полный доступ к хост-системе
- Это классический способ **выхода из контейнера** (container escape)
- Атакующий может:
  - Читать файловую систему хоста
  - Загружать kernel modules
  - Получить доступ к другим контейнерам
  - Компрометировать весь node

**К чему привело:**  
Pod был успешно создан (HTTP 201). Это указывает на **отсутствие PodSecurityPolicy/PodSecurityAdmission** или его неправильную настройку.

**Рекомендации:**
- Немедленно удалить pod: `kubectl delete pod privileged-pod -n secure-ops`
- Включить PodSecurity Admission с уровнем `restricted`
- Внедрить OPA Gatekeeper с constraint на запрет privileged контейнеров

---

### 3. Использование kubectl exec в чужом поде

| Параметр | Значение |
|----------|----------|
| **Тип** | POD_EXEC |
| **Severity** | HIGH |
| **Кто** | `minikube-user` |
| **Где** | namespace: `kube-system`, pod: `coredns-565d847f94-abc12` |
| **Что делал** | `cat /etc/resolv.conf` |
| **Когда** | 2026-01-30T18:00:07Z |

**Описание:**  
Выполнена команда внутри системного пода CoreDNS.

**Почему подозрительно:**  
- Exec в pod `kube-system` — редкая легитимная операция
- Даже безобидная команда `cat /etc/resolv.conf` может быть частью разведки
- Это может быть подготовкой к:
  - Инъекции вредоносного кода
  - Перехвату DNS-трафика
  - Lateral movement в кластере

**Рекомендации:**
- Настроить NetworkPolicy для изоляции `kube-system`
- Ограничить права `exec` через RBAC только для администраторов
- Настроить алерты на `pods/exec` в `kube-system`

---

### 4. Создание RoleBinding с правами cluster-admin

| Параметр | Значение |
|----------|----------|
| **Тип** | PRIVILEGE_ESCALATION |
| **Severity** | 🔴 CRITICAL |
| **Кто** | `minikube-user` |
| **Где** | namespace: `secure-ops`, binding: `escalate-binding` |
| **Когда** | 2026-01-30T18:00:08Z |

**Описание:**  
Создан RoleBinding `escalate-binding`, который привязывает ServiceAccount `monitoring` к ClusterRole `cluster-admin`.

**Почему подозрительно:**  
- `cluster-admin` даёт **полные права** на весь кластер
- Это классическая **эскалация привилегий** (privilege escalation)
- После этого ServiceAccount `monitoring` может:
  - Читать любые секреты
  - Создавать/удалять любые ресурсы
  - Полностью компрометировать кластер

**К чему привело:**  
RoleBinding был успешно создан. ServiceAccount `monitoring` теперь имеет права администратора в namespace `secure-ops`.

**Рекомендации:**
- Немедленно удалить: `kubectl delete rolebinding escalate-binding -n secure-ops`
- Запретить привязку к `cluster-admin` через OPA Gatekeeper
- Внедрить approval workflow для изменений RBAC

---

### 5. Удаление audit-policy / системных конфигов

| Параметр | Значение |
|----------|----------|
| **Тип** | KUBE_SYSTEM_MODIFICATION |
| **Severity** | HIGH |
| **Кто** | `minikube-user` |
| **Где** | namespace: `kube-system`, resource: `configmaps/extension-apiserver-authentication` |
| **Когда** | 2026-01-30T18:00:09Z |

**Описание:**  
Удалён системный ConfigMap `extension-apiserver-authentication`.

**Почему подозрительно:**  
- Модификация ресурсов в `kube-system` — критическая операция
- Удаление конфигов аутентификации может:
  - Нарушить работу API Server
  - Ослабить безопасность кластера
- Это может быть попыткой **заметания следов** или **саботажа**

**Возможные последствия:**
- Сбой в работе extension API servers
- Проблемы с агрегированными API
- Необходимость пересоздания ConfigMap

**Рекомендации:**
- Восстановить ConfigMap из backup или перезапустить kube-apiserver
- Ограничить права на delete в `kube-system` через RBAC
- Настроить immutable configmaps для критичных ресурсов

---

## Вывод

### Что произошло

Анализ показывает **последовательность действий типичной атаки** на Kubernetes кластер:

1. **Разведка** — попытки чтения секретов для понимания структуры кластера
2. **Закрепление** — создание privileged pod для возможного выхода на хост
3. **Латеральное движение** — exec в системные поды
4. **Эскалация привилегий** — получение прав cluster-admin
5. **Заметание следов** — удаление системных конфигов

### Ошибки в политике RBAC

1. **Отсутствует PodSecurityAdmission** — privileged pods создаются без ограничений
2. **Слишком широкие права** — пользователь `minikube-user` может:
   - Создавать RoleBinding с любыми ClusterRole
   - Выполнять exec в системные поды
   - Удалять ресурсы в `kube-system`
3. **Нет ограничений на привязку к cluster-admin** — любой может эскалировать привилегии
4. **Нет namespace isolation** — поды из `secure-ops` могут пытаться обращаться к `kube-system`

### Рекомендации по устранению

| Приоритет | Действие |
|-----------|----------|
| 🔴 P0 | Удалить `privileged-pod` и `escalate-binding` |
| 🔴 P0 | Включить PodSecurity Admission (level: restricted) |
| 🟠 P1 | Внедрить OPA Gatekeeper с правилами на privileged и cluster-admin |
| 🟠 P1 | Ограничить права на exec/delete в kube-system |
| 🟡 P2 | Настроить NetworkPolicy для namespace isolation |
| 🟡 P2 | Настроить алерты в SIEM на выявленные паттерны |

---

## Приложения

- `audit-extract.json` — выжимка подозрительных событий из audit.log
- `filter_audit.py` — скрипт фильтрации для автоматизации анализа
- `audit-policy.yaml` — конфигурация политики аудита Kubernetes
