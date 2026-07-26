# Отчёт пентеста: nskavtovokzal.ru
**Дата:** 2026-07-26 12:18
**Цель:** https://nskavtovokzal.ru
**Всего находок:** 21

## Сводка

| Критичность | Кол-во |
|------------|--------|
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 4 |
| LOW | 5 |
| INFO | 9 |

## Находки

### [HIGH] HSTS отсутствует
```
Заголовок strict-transport-security не установлен
```

### [HIGH] CSP отсутствует — возможны XSS атаки
```
Заголовок content-security-policy не установлен
```

### [HIGH] Возможный Time-Based SQL Injection в 'id'
```
URL: https://nskavtovokzal.ru/news-page?id=1%3B+SELECT+SLEEP%282%29--
Задержка: 1.9с
```

### [MEDIUM] Сайт доступен по HTTP без редиректа на HTTPS

### [MEDIUM] X-Frame-Options отсутствует — возможен Clickjacking
```
Заголовок x-frame-options не установлен
```

### [MEDIUM] X-Content-Type-Options отсутствует
```
Заголовок x-content-type-options не установлен
```

### [MEDIUM] Cookie без флага Secure
```
PHPSESSID=imsjbornhrikvvju6vr2j9guho; path=/; HttpOnly
```

### [LOW] Referrer-Policy отсутствует
```
Заголовок referrer-policy не установлен
```

### [LOW] Permissions-Policy отсутствует
```
Заголовок permissions-policy не установлен
```

### [LOW] Server заголовок раскрывает версию: nginx
```
Злоумышленник может найти известные CVE
```

### [LOW] Cookie без флага SameSite
```
PHPSESSID=imsjbornhrikvvju6vr2j9guho; path=/; HttpOnly
```

### [LOW] Email адреса в HTML (1)
```
info@nskavtovokzal.ru
```

### [INFO] IP адрес: 45.90.34.93

### [INFO] TLS версия: TLSv1.3

### [INFO] Обнаруженные технологии
```
Nginx
```

### [INFO] Robots.txt раскрывает скрытые пути
```
/admin/
/order/pay
/*?
```

### [INFO] Reflected XSS: автоматическая проверка не выявила уязвимостей
```
Требуется ручное тестирование форм
```

### [INFO] SQL Injection: error-based проверка чиста
```
Требуется ручное тестирование + blind SQLi
```

### [INFO] Телефоны в HTML (2)
```
+73833559990
+7 (383) 355-99-90
```

### [INFO] robots.txt: 3 Disallow правил
```
/admin/
/order/pay
/*?
```

### [INFO] Sitemap найден: 39 URL
```
https://nskavtovokzal.ru/sitemap.xml
```

