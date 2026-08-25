# gost-upstream

GOST TLS (Магма/Кузнечик, ГОСТ Р 34.10-2012) upstream-прокси для Burp Suite
и любого другого инструмента, умеющего работать через upstream HTTP-прокси.

Burp (или другой клиент) никогда не касается ГОСТ-криптографии напрямую:
он видит обычный TLS-сертификат на нужное имя, подписанный локальным CA.
Настоящий ГОСТ TLS 1.2 хендшейк с целью делает отдельная VM с
[gost-engine](https://github.com/gost-engine/engine), до которой мы
достаём по SSH. Для целей с обычным TLS запрос уходит напрямую, без VM.

> ⚠️ **Легальность.** Это MITM-инструмент, перехватывающий и расшифровывающий
> TLS-трафик. Используйте его только на системах, которые вы либо
> контролируете сами, либо на тестирование которых у вас есть явное
> разрешение (авторизованный пентест, bug bounty со scope и т.п.).
> Перехват чужого трафика без разрешения — уголовно наказуем практически
> везде. Авторы и контрибьюторы не несут ответственности за то, как вы
> это используете, — инструмент предоставляется "как есть", без каких-либо
> гарантий (см. [LICENSE](LICENSE), MIT).

## Как это работает

1. Клиент (Burp) подключается к `gost-upstream` как к upstream-прокси и
   шлёт `CONNECT host:port`.
2. `gost-upstream` термирует TLS с клиентом сертификатом, подписанным
   собственным CA (свежесгенерированным на лету под конкретный host).
3. Пытается достучаться до цели обычным TLS. Если не вышло (нет общего
   cipher suite — типичный симптом ГОСТ-only сайта), автоматически
   ретраит через VM: `ssh <vm> 'openssl s_client -cipher <GOST suites>
   -connect host:port'`, с уже загруженным `gost-engine`.
4. Ответ уходит обратно клиенту как обычный TLS.

Никакой ручной разметки "какие хосты ГОСТ, какие нет" не нужно — прокси
сам определяет это по результату хендшейка.

## Сборка

```
cargo build --release
```

### Кросс-сборка под Windows

```
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64   # линковщик для этого таргета
cargo build --release --target x86_64-pc-windows-gnu -p gost-upstream
```

Бинарник: `target/x86_64-pc-windows-gnu/release/gost-upstream.exe`. Для
работы ГОСТ-фолбэка на Windows нужен `ssh.exe` в PATH (штатный OpenSSH
Client — Settings → Apps → Optional features, в современных Windows часто
уже включён).

Неподписанный `.exe`, который генерирует сертификаты на лету, перехватывает
TLS и спавнит дочерние процессы, — типичный кандидат на эвристический
false positive в антивирусах (HackTool/PUA-класс детектов). Это ожидаемо
для инструментов такого профиля, не специфично для Rust. На практике
собранный так `.exe` проверен на живой Windows 10 VM с Defender'ом — не
ругается.

### Нативная сборка на Windows

Если собирать прямо на Windows-машине, а не кросс-компилировать с Linux —
`cargo` кросс-платформенный, команды те же самые:

1. Поставить Rust: [rustup-init.exe](https://rustup.rs) (или
   `winget install Rustlang.Rustup`).
2. Rustup по умолчанию ставит MSVC-таргет (`x86_64-pc-windows-msvc`), для
   него нужен C++ тулчейн — rustup сам предложит поставить
   "Visual Studio C++ Build Tools" при первой сборке, либо поставить
   заранее вручную (компонент "Desktop development with C++").
3. Дальше — ровно та же команда, что и на Linux, в PowerShell или cmd:

```powershell
cargo build --release
```

Бинарник: `target\release\gost-upstream.exe`. Требование по `ssh.exe` в
PATH для ГОСТ-фолбэка — то же самое, что и в кросс-собранной версии.

## Настройка VM с gost-engine

Нужна отдельная машина (Linux) с собранным
[gost-engine](https://github.com/gost-engine/engine) и passwordless SSH
с хоста, где крутится `gost-upstream`.

```
git clone https://github.com/gost-engine/engine ~/gost-engine
cd ~/gost-engine && git submodule update --init
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
sudo cmake --build . --target install --config Release
```

Дальше создать на VM конфиг (например `~/gost.cnf`):

```
openssl_conf = openssl_def
[openssl_def]
engines = engine_section
[engine_section]
gost = gost_section
[gost_section]
engine_id = gost
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/gost.so
default_algorithms = ALL
```

Путь `dynamic_path` — вывод `openssl version -e` подскажет актуальный
`ENGINESDIR` на вашей системе; замените на реальный, если он другой.

**Важно:** движок должен грузиться именно через `OPENSSL_CONF=~/gost.cnf`,
а НЕ через флаг `-engine` — это известная проблема
([openssl/openssl#5809](https://github.com/openssl/openssl/issues/5809)):
при `-engine` cipher suite сканируются раньше, чем движок успевает
подключиться, и остаются недоступны. Проверить, что всё встало:

```
OPENSSL_CONF=~/gost.cnf openssl ciphers -v "ALL:COMPLEMENTOFALL" | grep -i gost
```

Должны появиться `GOST2012-MAGMA-MAGMAOMAC`, `GOST2012-KUZNYECHIK-KUZNYECHIKOMAC`
и легаси-варианты.

## Запуск

```
./target/release/gost-upstream --ssh-target user@vm-host
```

Полный список опций: `--help`. По умолчанию слушает `127.0.0.1:8888`,
CA генерируется в `gost-upstream-ca.pem`/`gost-upstream-ca-key.pem` в
текущей директории.

## Настройка Burp Suite

1. **Settings → Network → Connections → Upstream Proxy Servers** — добавить
   правило: destination host `*` (или паттерн под конкретные цели),
   proxy host `127.0.0.1`, port `8888`.
2. **Settings → Network → TLS → Custom CA certificates → Add** —
   импортировать `gost-upstream-ca.pem`. Это отдельная настройка от той,
   что ставит CA-сертификат Burp в браузер — тут наоборот, сам Burp
   должен доверять НАШЕМУ CA при проверке сертификатов целевых серверов.

Без второго шага Burp будет показывать ошибку валидации сертификата на
каждый запрос — сертификат от `gost-upstream` подписан неизвестным Burp'у
CA.

После этого Burp работает с ГОСТ-защищёнными сайтами как с обычными —
Proxy history, Repeater, Intruder, Scanner видят расшифрованный трафик,
сам Burp ни разу не касается ГОСТ-криптографии.

## Ограничения

- Каждый запрос через VM — это отдельный `ssh`+`openssl s_client`
  процесс. Под высокой конкурентностью (Intruder/Scanner на больших
  наборах payload'ов) это может быть узким местом.
- Для генуинно недоступных хостов (не резолвится, не отвечает) первый
  запрос платит двойную попытку: обычный TLS + до ~10 секунд ожидания
  первого байта от VM, прежде чем вернуть ошибку.
- Без `--ssh-target` работает как обычный MITM без ГОСТ-фолбэка —
  полезно для проверки самого прокси и сертификатов без VM.

## Лицензия

MIT — см. [LICENSE](LICENSE).

## Разработка

Написан в паре с [Claude Code](https://claude.com/claude-code).
