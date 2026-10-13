# PRISM

**PRISM** (Protocol for Reality-Injected Steganographic Multiplexing) — транспорт на Rust, который проводит VPN-трафик внутри сессии, похожей на обычный Chrome HTTP/3 (QUIC) к настоящему CDN.

Репозиторий: [github.com/Hiken333/prisma-protocol](https://github.com/Hiken333/prisma-protocol).

Лицензия: MIT OR Apache-2.0.

## Как это работает

Клиент поднимает TUN-интерфейс. Каждый IP-пакет из него уходит на сервер, сервер пишет его в свой TUN (или, в тестовом режиме, возвращает обратно). Снаружи это выглядит как QUIC к сайту-приманке (`--decoy`, по умолчанию `www.cloudflare.com`).

```
приложение
    │  IP-пакет
    ▼
TUN (wintun / tun)
    │  5-tuple → QUIC stream
    ▼
MCC: тело пакета = тело STREAM-фрейма, без своего VPN-заголовка
    │
    ▼
morph: размер и пауза берутся из профиля настоящего CDN
    │
    ▼
QUIC + TLS (BoringSSL)  ──UDP──►  сервер
    │                                    │
    │  после рукопожатия, в быстром      │
    │  режиме данные уходят в BOLT       │
    ▼                                    ▼
AES-GCM кадры на UDP base+1..base+N     TUN сервера → интернет
```

Дальше по шагам.

### 1. Рукопожатие Reality

Пароля в пакете нет. У сервера есть долгоживущий секрет X25519 (`shadow_sk`). Клиенту выдают только публичную половину (`shadow_pk`) и имя decoy.

1. Клиент генерирует эфемерную пару X25519.
2. Общий секрет: `X25519(эфемерный_секрет, shadow_pk)`.
3. Метка: `HMAC-SHA256(общий_секрет, decoy_sni)`.
4. Публичный эфемерный ключ кладётся в TLS `key_share`, метка — в GREASE-расширение ClientHello. На проводе это по-прежнему ClientHello Chrome.

Сервер разбирает ClientHello **до** обычного TLS и в постоянном времени сравнивает метку. Совпало — это сессия PRISM. Не разобралось, метка не сошлась или это обычный браузер — соединение прозрачно проксируется на настоящий origin (`--decoy-origin`). Отдельного ответа «доступ запрещён» нет: зонд видит тот же сайт, что и живой CDN.

Повтор 0-RTT отсекается вращающимся bloom-фильтром (`prism-auth`).

### 2. Общие секреты из TLS exporter

Одно рукопожатие даёт 48 байт `prism/master` (TLS exporter). Обе стороны разводят из него одни и те же ключи через HKDF, без дополнительных пакетов:

| Метка | Зачем |
| --- | --- |
| `prism/bbr/seed` | Начальное состояние контроля перегрузки |
| `prism/morph/up` | ГСЧ формы исходящих пакетов |
| `prism/morph/dn` | ГСЧ формы входящих (независимый поток) |
| `prism/ticket` | Ключ расширения session ticket |
| `prism/bolt/up` | AES-GCM клиент → сервер |
| `prism/bolt/dn` | AES-GCM сервер → клиент |

### 3. Mirror-Cell Carrying

IP-пакет из TUN пишется **как есть** в тело QUIC STREAM. Отдельных полей `vpn_type` / `vpn_length` / `vpn_checksum` нет: номер потока, offset и длина — это и есть метаданные.

Поток выбирается по 5-tuple (адреса, порты, протокол), чтобы потеря в одном TCP-соединении не стопорила остальные. Клиент открывает двунаправленные потоки (`id % 4 == 0`). В обычном режиме пул — 8 потоков, в `--perf` — 64.

### 4. Форма трафика и перегрузка

`prism-morph` хранит гистограмму размеров, межпакетных пауз и пачек, снятую с настоящего decoy. `MorphEngine` сэмплирует из неё цель для следующего UDP-датаграммы. Паддинг — кадры QUIC `PADDING` **внутри** AEAD, чтобы размер на проводе совпал с профилем и пакет не фрагментировался. Нижняя граница цели — 200 байт, верхняя — MTU−48.

`prism-cc` ведёт окно BBRv3, посеянное из exporter. При потерях включается brutal-режим в духе Hysteria 2: фиксированный темп вместо отката окна. `MorphBudget` вставляет паузы, похожие на CDN. Если свой контроллер нельзя вставить в quiche, снаружи стоит `CcGate`: quiche работает с BBRv2 и выключенным внутренним pacing, а реальное окно держит PRISM.

### 5. BOLT — быстрый тракт данных

В режиме `--perf` / `PRISM_PERF=1` / `PRISM_FAST=1` / `PRISM_BOLT=1` полезная нагрузка после рукопожатия уходит с QUIC-потоков на отдельные UDP-порты `base+1 … base+N` (по умолчанию 8 полос, от 2 до 8 через `PRISM_BOLT_LANES`). QUIC остаётся только чтобы держать сессию и NAT.

Кадр фиксированной длины (4096 байт, степень двойки до 16384, `PRISM_BOLT_WIRE_SIZE`):

```
nonce (12) || AES-GCM(
    "B1" | flags | seq u32 | n_chunks |
    повтор: u16 длина | IP-пакет
) || tag (16)
```

В один кадр пакуется несколько IP-пакетов. `BrutalPacer` ограничивает темп: по умолчанию потолок 300 Мбит/с, не выше 500 (`PRISM_BOLT_MBPS`). Направления шифруются разными ключами.

### 6. FEC

`prism-fec` — Reed-Solomon, по умолчанию 10 блоков данных + 2 блока чётности. Любые 10 из 12 восстанавливают группу без повторной передачи.

### Два транспорта

Одна и та же логика auth / morph / cc сидит на двух проводах.

| | Native (`prism-transport`) | quiche + BoringSSL |
| --- | --- | --- |
| Зависимости | только Rust | C/C++ toolchain, cmake, nasm, perl |
| Провод | свой UDP: INIT с магией `PRZM`, затем короткий заголовок `0x40` + номер пакета. Номер пакета — nonce ChaCha20-Poly1305 | настоящий QUIC, ClientHello как у Chrome |
| Когда | самопроверка и сеть без нативной сборки | TUN и отпечаток, похожий на браузер |

Native совместим сам с собой. Байт-в-байт с Chrome он не совпадает.

## Крейты

| Крейт | Роль |
| --- | --- |
| `prism-core` | типы, конфиг, X25519/HKDF/HMAC, `PrismExporter`, посеянный ГСЧ |
| `prism-auth` | Reality: метка в ClientHello, решение «сессия или decoy», anti-replay |
| `prism-cc` | `BbrPrism`, brutal mode, `MorphBudget`, `CcGate` |
| `prism-morph` | профиль CDN, `MorphEngine`, энтропия, адаптация под троттлинг |
| `prism-quic` | трейт `QuicBackend`, MCC, цикл отправки, TUN-туннель, BOLT |
| `prism-transport` | чистый Rust UDP-транспорт |
| `prism-bolt` | параллельные AES-GCM полосы |
| `prism-fec` | Reed-Solomon 10+2 |
| `prism-decoy` | прозрачный прокси зонда на настоящий origin (UDP/TCP/QUIC VN) |
| `prism-tun` | TUN (`tun` / `wintun`) и привязка потока к 5-tuple |
| `prism-client` | клиент: TUN ↔ движок ↔ UDP |
| `prism-server` | сервер: UDP ↔ движок ↔ {PRISM \| decoy} |
| `prism-eval` | KL-дивергенция размеров и пауз, энтропия, сверка JA4 |

Почему BoringSSL, а не rustls: Chrome собран на BoringSSL, и порядок шифров, расширений и GREASE в ClientHello совпадает почти бесплатно. `rustls` остаётся только для офлайн-криптографии, которая на провод не попадает.

quiche из crates.io подменён тонким форком (`patches/`, сборка через `scripts/vendor-quiche.ps1`). Форк открывает экспортёр TLS, паддинг кадра до заданного размера и свой контроллер перегрузки. Подробности — в [`docs/quiche-fork.md`](docs/quiche-fork.md). Каталог `third_party/` в git не входит: BoringSSL слишком большой, его воспроизводит скрипт.

## Сборка

Нужен Rust 1.75+.

```bash
cargo build --workspace
cargo test  --workspace
cargo build -p prism-quic --features quiche-backend
```

Первые две команды собирают логику без нативного QUIC. Третья включает настоящий quiche и требует C/C++ toolchain.

На Windows, если PowerShell ругается на выполнение сценариев:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
. .\scripts\dev-env.ps1
cargo build -p prism-quic --features quiche-backend
```

Политика меняется только в этом окне терминала.

## Запуск

Самопроверка по loopback UDP, без второго хоста:

```bash
cargo run -p prism-client -- --selftest --count 5
```

Два хоста, native-транспорт:

```bash
cargo run -p prism-server -- --listen 0.0.0.0:4433 --decoy www.cloudflare.com
# в логе: shadow_pk=<HEX>
# зонд уходит на настоящий сайт, если задан --decoy-origin www.cloudflare.com:443

cargo run -p prism-client -- --server <SERVER_IP>:4433 --shadow-pk <HEX> --count 10
```

Без `--shadow-sk` сервер каждый запуск генерирует новый ключ и печатает `shadow_pk`. Клиент с чужим decoy (и значит с другой меткой) не получает отдельного отказа.

TUN (нужны фичи `quiche-backend` и `tunnel`):

```bash
prism-server --listen 0.0.0.0:4433 --shadow-sk <HEX> --cert cert.pem --key key.pem --tun --tun-cidr 172.19.0.1/30

prism-client --tun --server <IP>:4433 --shadow-pk <HEX> --tun-cidr 172.19.0.2/30
```

Серверный адрес в `/30` — первый хост, клиентский — следующий (`172.19.0.1` → клиент `172.19.0.2`). Docker-выкладка тестового сервера описана в [`deploy/README.md`](deploy/README.md).

## Режимы скорости

Скрытность — режим по умолчанию, и она режет пропускную способность. Оба конца нужно переключать вместе: каждая сторона задаёт форму **своей** отправки, а скачивание определяет сервер.

| Режим | Как включить | Что меняется |
| --- | --- | --- |
| Stealth | ничего | CUBIC, каждая датаграмма добивается до размера из профиля CDN |
| Быстрый morph | `PRISM_FAST=1` | паддинг размеров выключен, контроллер прежний |
| Perf | `PRISM_PERF=1` или `--perf` | без паддинга, BBR, без pacing, пакетный приём/отправка, пул 64 потока, данные по BOLT |

Отпечаток рукопожатия (JA4 / ClientHello) во всех режимах один. Perf жертвует формой трафика: размеры и паузы перестают повторять CDN.

Полезные переменные BOLT: `PRISM_BOLT=1`, `PRISM_BOLT_LANES` (2–8), `PRISM_BOLT_MBPS` (потолок, не выше 500), `PRISM_BOLT_WIRE_SIZE` (4096…16384, степень двойки), `PRISM_BOLT_TURBO`.

Сокеты UDP во всех режимах поднимают буфер до 4 МиБ. На Windows клиент просит таймер 1 мс, иначе tokio квантует таймеры потерь примерно до 15.6 мс.

## Что уже совпадает с Chrome, а что нет

| Свойство | Состояние |
| --- | --- |
| JA4 ClientHello (Chrome 148 h3) | совпадает, эталон в `ci/baseline/chrome_148.ja4` |
| Байт-в-байт ClientHello (`X25519MLKEM768`, два Initial) | известный зазор, низкий приоритет: JA4 уже совпадает |
| Форма на проводе (размер, пауза, энтропия) | проверяется `morph_fidelity` и `prism-eval --live` |

Полная проверка на Windows:

```powershell
.\scripts\validate.ps1 -OutDir testdata
```
