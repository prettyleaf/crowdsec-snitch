# crowdsec-snitch

Превращает баны CrowdSec в жалобы хостингу атакующего: находит abuse-контакт, собирает строки логов этого IP и готовит письмо с вложением. Рассчитан на связку SWAG + CrowdSec из [руководства linuxserver.io](https://www.linuxserver.io/blog/blocking-malicious-connections-with-crowdsec-and-swag), когда SWAG не стоит за CDN.

```
логи SWAG → CrowdSec → бан → http-уведомление → crowdsec-snitch → письмо на abuse@
```

По умолчанию работает в режиме `dry-run`: письма только сохраняются в файлы, и ничего не отправляется.

## Перед включением отправки

Политики [Resend](https://resend.com/legal/acceptable-use) и [smtp.bz](https://smtp.bz/anti-spam) требуют согласия получателей на письма. Resend также может закрыть аккаунт без предупреждения, если возвраты превысят 4% или жалобы 0,08%. Абьюз-отчёты на служебный адрес `abuse@` под эти правила формально могут попасть, поэтому **до режимов `approve` и `auto` спросите поддержку провайдера**, допустимы ли такие письма. Сервис работает с любым SMTP с аутентификацией, так что можно использовать и ящик на собственном домене.

## Установка

1. Создайте каталог данных и файл настроек:

   ```bash
   sudo install -d -o 1000 -g 1000 /opt/appdata/crowdsec-snitch
   cp .env.example .env
   openssl rand -hex 32   # значение для SNITCH_TOKEN
   ```

   В `.env` также укажите `SNITCH_TARGET` (публичный IP вашего сервера), `SNITCH_ALLOW_CIDRS` (свои сети) и `SNITCH_REDACT` (свои домены).

2. Проверьте пути и сеть в `compose.yaml` и запустите сервис:

   ```bash
   docker compose up -d --build
   ```

   Пользователь контейнера должен иметь право читать логи SWAG. По умолчанию это UID 1000, как `PUID` в руководстве.

3. Скопируйте `crowdsec/notifications/abuse_webhook.yaml` в `/opt/appdata/crowdsec/config/notifications/` и подставьте токен.

4. В `/opt/appdata/crowdsec/config/profiles.yaml` добавьте уведомление в профиль с баном IP:

   ```yaml
   name: default_ip_remediation
   filters:
     - Alert.Remediation == true && Alert.GetScope() == "Ip"
   decisions:
     - type: ban
       duration: 4h
   notifications:
     - abuse_webhook
   on_success: break
   ```

5. Перезапустите CrowdSec и проверьте связь:

   ```bash
   docker restart crowdsec
   docker exec crowdsec cscli notifications test abuse_webhook
   docker logs crowdsec-snitch --tail 20
   docker exec crowdsec-snitch snitch stats
   ```

   В логе должно появиться `received 1 alert(s)`. Тестовый алерт отсеивается, поэтому в `stats` появится строка `skipped`. CrowdSec не повторяет запрос при ответе вне диапазона 2xx: при неверном токене алерт теряется, а причина видна только в логах CrowdSec.

6. Проверьте сборку настоящего письма на реальном алерте:

   ```bash
   docker exec crowdsec cscli alerts list
   docker exec crowdsec cscli notifications reinject ALERT_ID
   ```

## Запуск по этапам

| Этап | `SNITCH_MODE` | Что происходит |
|---|---|---|
| 1. Проверка, 1–2 недели | `dry-run` | Письма только сохраняются в `/data/outbox` |
| 2. Ручное одобрение | `approve` | Письма ждут одобрения, раз в день приходит сводка на `SNITCH_OPERATOR_EMAIL` |
| 3. Автоматика | `auto` | Письма уходят сразу, в пределах лимитов |

После смены режима выполните `docker compose up -d`. История dry-run не мешает настоящим отправкам. Перед этапом 2 проверьте SMTP:

```bash
docker exec crowdsec-snitch snitch test-smtp you@example.org
```

Настройки Resend уже есть в `.env.example`. Для smtp.bz возьмите хост, порт, логин и пароль в личном кабинете: в публичной документации найти их не удалось.

## Команды

```bash
alias snitch='docker exec crowdsec-snitch snitch'

snitch stats                # сколько отчётов и почему отсеяны
snitch list                 # последние отчёты
snitch list --status pending
snitch show ID              # письмо и вложение целиком
snitch approve ID [ID...]   # отправить; подходит и для повтора статуса failed
snitch approve --all        # все ожидающие
snitch reject ID [ID...]    # отклонить
```

## Что отсеивается

Причину пропуска показывает `snitch stats`.

| Причина | Значение |
|---|---|
| `scenario_not_selected` | Сценарий не входит в список. По умолчанию это эксплойты с CVE, `netgear_rce`, `vmware-vcenter-vmsa-*`, `http-backdoors-attempts`, `http-sensitive-files`, `ssh-bf*`, `ssh-slow-bf*`. Шумные `http-probing`, `http-crawl-non_statics` и `http-cve-probing` не входят |
| `no_local_ban`, `simulated`, `not_single_ip` | Не настоящий бан одного IP от самого CrowdSec: ручное решение, симуляция или диапазон |
| `non_public_ip`, `invalid_ip`, `allowlisted` | Частный или некорректный адрес, либо ваша сеть |
| `not_hosting`, `mobile_network`, `proxy_vpn_tor` | Домашний, мобильный адрес, прокси, VPN или Tor |
| `duplicate` | На этот IP уже был отчёт за `SNITCH_DEDUPE_DAYS` |
| `contact_limit`, `daily_limit` | Превышен дневной лимит на контакт или общий |
| `no_abuse_contact`, `no_evidence`, `lookup_failed` | Нет контакта, нет данных для отчёта или поиск не удался за 5 попыток |

## Как это работает и что учесть

- **Контакт:** сначала [Abusix Abuse Contact DB](https://docs.abusix.com/docs/abuse-reporting/abuse-contact-db/getting-started) по DNS, затем RDAP. В письмо добавляется просимая Abusix ссылка на источник.
- **Определение хостинга:** [ip-api.com](https://ip-api.com/docs/api:json). Бесплатный тариф работает только по HTTP и не разрешает коммерческое использование. Классификация эвристическая. Отключается через `SNITCH_REQUIRE_HOSTING=false`, но тогда жалобы будут уходить и на домашние адреса.
- **Доказательства:** берутся строки `access.log*`, включая `.gz`, за окно времени вокруг алерта. Строка относится к IP, только если адрес стоит в поле клиента, иначе можно было бы подставить чужой IP в `User-Agent`. Ожидается формат nginx `combined`, который SWAG использует по умолчанию. Для SSH вложение содержит только события CrowdSec, поэтому `/var/log/auth.log` монтировать не нужно.
- **Очистка:** значения параметров вроде `token` и `key` и строки из `SNITCH_REDACT` заменяются на `[redacted]`, управляющие символы и не-ASCII экранируются. Перед этапом 2 всё равно просмотрите несколько писем через `snitch show`.
- **Хранение:** файлы писем лежат в `/data/outbox` и автоматически не удаляются.

## Разработка

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```
