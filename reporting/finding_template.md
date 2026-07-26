# Шаблон описания уязвимости

## [VULN-XXX] Название уязвимости

**Критичность:** Critical / High / Medium / Low / Informational  
**CVSS Score:** X.X (вектор: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**Тип:** CWE-XXX  
**URL/Компонент:** https://nskavtovokzal.ru/...  

---

### Описание

Краткое описание уязвимости и её природы.

### Доказательство (PoC)

```
# Запрос
GET /vulnerable/endpoint?param=payload HTTP/1.1
Host: nskavtovokzal.ru

# Ответ
HTTP/1.1 200 OK
...уязвимый ответ...
```

### Влияние

Что злоумышленник может сделать при эксплуатации.

### Рекомендация

Как исправить уязвимость.

### Ссылки

- https://owasp.org/...
- https://cwe.mitre.org/data/definitions/XXX.html
