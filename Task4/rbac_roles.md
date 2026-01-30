# Ролевая модель доступа (RBAC) PropDevelopment

| Роль (Role Name) | Тип | Полномочия (Permissions) | Группы пользователей / Субъекты |
| :--- | :--- | :--- | :--- |
| **view-only** | ClusterRole | **Чтение:** `get`, `list`, `watch`<br>**Ресурсы:** `pods`, `deployments`, `services`, `configmaps`, `nodes` | `developers` (Разработчики), `qa` (Тестировщики) |
| **cluster-admin** | ClusterRole | **Полный доступ:** `*`<br>**Ресурсы:** `*` | `admins` (DevOps инженеры, Архитекторы) |
| **namespace-admin** | Role | **Полный доступ в NS:** `*`<br>**Ресурсы:** `*` (кроме nodes, pv) | `product-owner` (Владельцы продуктов) |
| **secret-reader** | Role | **Чтение:** `get`, `list`<br>**Ресурсы:** `secrets` | `security-audit` (Аудиторы ИБ), `lead-dev` |
