import telebot
import subprocess
import uuid
import os
import json
import time
import re
import secrets
import ssl
import threading
import concurrent.futures
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
from io import BytesIO

import qrcode
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TOKEN = os.getenv('BOT_TOKEN')
bot = telebot.TeleBot(TOKEN)

ADMIN_TELEGRAM_ID = int(os.getenv('ADMIN_TELEGRAM_ID', '0'))

VPN_CONTAINER_NAME = "ovpn-server"
STATUS_LOG = "/tmp/openvpn-status.log"
HISTORY_FILE = "/tmp/bandwidth_history.json"
BW_LIMIT = 1_000_000_000  # 1 Gbps in bits/sec

OLCRTC_IMAGE = "olcrtc-server:latest"
OLCRTC_JITSI_INSTANCE = "meet.egovm.ru"  # проверено вручную, что открывается в белых списках
JITSI_HOST_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}\.)+[a-zA-Z]{2,}$')

JITSI_LIST_URL = "https://raw.githubusercontent.com/denpiligrim/jitsi-scanner/main/found_jitsi_domains.txt"
JITSI_SCAN_TIMEOUT = 3      # сек на один хост (latency-скан)
JITSI_SCAN_WORKERS = 8      # конкурентность, без фанатизма
JITSI_SCAN_PROGRESS_MIN_INTERVAL = 2  # сек между обновлениями статуса в чате

JITSI_SPEED_CONNECT_TIMEOUT = 3     # сек на установку соединения
JITSI_SPEED_TARGET_BYTES = 20_000_000  # качаем хотя бы 20 МБ на хост для честного замера
JITSI_SPEED_SAFETY_SECONDS = 30     # защитный потолок на хост, если он слишком медленный/зависает
JITSI_SPEED_WORKERS = 8             # конкурентность для speed-скана, без фанатизма

TELEGRAM_MSG_LIMIT = 3500  # запас от лимита телеграма в 4096 символов на сообщение

KNOWN_WHITE_FLAGS = {"-best_ms", "-best_mb", "-best_all", "-test", "-default", "-checkoff"}

DATA_DIR = "/data"  # смонтирован как volume, переживает пересборку/рестарт бота
CLIENT_NAMES_FILE = os.path.join(DATA_DIR, "client_names.json")   # {real_name: alias}
WHITE_CONFIGS_FILE = os.path.join(DATA_DIR, "white_configs.json")  # {container_name: {...}}
DEFAULT_JITSI_FILE = os.path.join(DATA_DIR, "default_jitsi.json")  # {"host": "..."}
WHITESUB_POOL_FILE = os.path.join(DATA_DIR, "whitesub_pool.json")  # {"hosts": [...], "updated_at": ts}
JITSI_DENYLIST_FILE = os.path.join(DATA_DIR, "jitsi_denylist.json")  # {"hosts": [...]}
WHITESUB_TOKEN_FILE = os.path.join(DATA_DIR, "whitesub_token.json")  # legacy, только для миграции
WHITESUB_LAST_TEXT_FILE = os.path.join(DATA_DIR, "whitesub_last.txt")  # legacy, только для миграции
WHITESUB_META_FILE = os.path.join(DATA_DIR, "whitesub_meta.json")  # legacy, только для миграции
WHITESUB_SUBSCRIPTIONS_FILE = os.path.join(DATA_DIR, "whitesub_subscriptions.json")
# {"active_id": "wsub-xxxx", "subscriptions": {"wsub-xxxx": {"name","token","last_text","created_at"}}}

SUB_HTTPS_PORT = int(os.getenv("SUB_HTTPS_PORT", "8443"))
SUB_CERT_DIR = os.path.join(DATA_DIR, "certs")
SUB_CERT_FILE = os.path.join(SUB_CERT_DIR, "cert.pem")
SUB_KEY_FILE = os.path.join(SUB_CERT_DIR, "key.pem")
PUBLIC_HOST = os.getenv("PUBLIC_HOST", "")  # IP/домен, по которому клиент достучится до /sub/<token>

# Заведённые вручную по факту обнаруженной поломки: проходят HTTP-пробу (латенси/скорость),
# но реально не работают как jitsi-провайдер для olcrtc. Дозаполняется по мере находок.
SEED_JITSI_DENYLIST = [
    "meet.astrocard-iservice.com",  # "server does not advertise anonymous XMPP login"
]

WHITESUB_DEFAULT_COUNT = 5
WHITESUB_MAX_COUNT = 20  # разумный потолок, чтобы не наплодить контейнеров по ошибке

# message_id сообщения с конфигом -> real_name, для обработки ответа-переименования.
# Живёт только в памяти процесса: если бот перезапустится до ответа - просто
# отвалится возможность переименовать именно то сообщение, не критично.
pending_rename = {}

# message_id сообщения-запроса /whitesub -setup -> {"combined": [...], "count": N}.
# Тоже только в памяти - если бот перезапустится до ответа, придётся запускать -setup заново.
pending_whitesub_setup = {}

# message_id сводного сообщения /whitesub -> True, для переименования подписки по reply.
pending_whitesub_rename = {}

# message_id сообщения со списком "Конфигурация" -> True, для добавления/удаления
# серверов по reply. Не удаляется после ответа - можно отвечать многократно.
pending_whitesub_config = {}


def is_admin(message):
    return message.from_user.id == ADMIN_TELEGRAM_ID


def load_json_file(path, default):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return default
    return default


def save_json_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f)


def get_client_names():
    return load_json_file(CLIENT_NAMES_FILE, {})


def set_client_name(real_name, alias):
    names = get_client_names()
    names[real_name] = alias
    save_json_file(CLIENT_NAMES_FILE, names)


def get_white_configs():
    return load_json_file(WHITE_CONFIGS_FILE, {})


def save_white_config(container_name, data):
    configs = get_white_configs()
    configs[container_name] = data
    save_json_file(WHITE_CONFIGS_FILE, configs)


def get_whitesub_pool():
    """Список {"host","checks"}. Поддерживает и старый формат (просто список
    строк-доменов, до появления аннотаций проверок) - оборачивает на лету."""
    raw = load_json_file(WHITESUB_POOL_FILE, {}).get("hosts", [])
    return [
        entry if isinstance(entry, dict) else {"host": entry, "checks": None}
        for entry in raw
    ]


def save_whitesub_pool(entries):
    save_json_file(WHITESUB_POOL_FILE, {"hosts": entries, "updated_at": time.time()})


def add_whitesub_pool_host(host, checks):
    pool = get_whitesub_pool()
    pool.append({"host": host, "checks": checks})
    save_whitesub_pool(pool)


def remove_whitesub_pool_at(position):
    """position - 1-based индекс, как в отображаемом списке. Возвращает
    удалённую запись или None, если позиция вне диапазона."""
    pool = get_whitesub_pool()
    if not (1 <= position <= len(pool)):
        return None
    removed = pool.pop(position - 1)
    save_whitesub_pool(pool)
    return removed


def _migrate_legacy_whitesub_subscription():
    """Одноразовая миграция единственной старой подписки (meta+token+last_text
    из версии до мульти-подписок) в новое хранилище - чтобы уже выданная
    ссылка не сломалась при обновлении бота."""
    meta = load_json_file(WHITESUB_META_FILE, None)
    token_data = load_json_file(WHITESUB_TOKEN_FILE, None)
    if not meta or not token_data:
        return None

    last_text = None
    if os.path.exists(WHITESUB_LAST_TEXT_FILE):
        with open(WHITESUB_LAST_TEXT_FILE, "r", encoding="utf-8") as f:
            last_text = f.read()

    sub_id = meta["id"]
    return {
        "active_id": sub_id,
        "subscriptions": {
            sub_id: {
                "name": meta.get("name", "WhiteLite"),
                "token": token_data["token"],
                "last_text": last_text,
                "created_at": time.time(),
            }
        }
    }


def get_whitesub_store():
    data = load_json_file(WHITESUB_SUBSCRIPTIONS_FILE, None)
    if data:
        return data
    migrated = _migrate_legacy_whitesub_subscription()
    store = migrated or {"active_id": None, "subscriptions": {}}
    save_json_file(WHITESUB_SUBSCRIPTIONS_FILE, store)
    return store


def save_whitesub_store(store):
    save_json_file(WHITESUB_SUBSCRIPTIONS_FILE, store)


def create_whitesub_subscription(name=None):
    store = get_whitesub_store()
    sub_id = f"wsub-{secrets.token_hex(4)}"
    sub = {
        "name": name or "WhiteLite",
        "token": secrets.token_urlsafe(24),
        "last_text": None,
        "created_at": time.time(),
    }
    store["subscriptions"][sub_id] = sub
    store["active_id"] = sub_id
    save_whitesub_store(store)
    return sub_id, sub


def get_active_whitesub_subscription():
    """Возвращает (id, sub) активной подписки, создавая первую подписку
    по умолчанию, если их вообще ещё нет."""
    store = get_whitesub_store()
    active_id = store.get("active_id")
    if active_id and active_id in store["subscriptions"]:
        return active_id, store["subscriptions"][active_id]
    if store["subscriptions"]:
        sub_id = next(iter(store["subscriptions"]))
        store["active_id"] = sub_id
        save_whitesub_store(store)
        return sub_id, store["subscriptions"][sub_id]
    return create_whitesub_subscription()


def set_active_whitesub_subscription(sub_id):
    store = get_whitesub_store()
    if sub_id not in store["subscriptions"]:
        return False
    store["active_id"] = sub_id
    save_whitesub_store(store)
    return True


def rename_whitesub_subscription(sub_id, name):
    store = get_whitesub_store()
    if sub_id not in store["subscriptions"]:
        return False
    store["subscriptions"][sub_id]["name"] = name
    save_whitesub_store(store)
    return True


def save_whitesub_subscription_text(sub_id, text):
    store = get_whitesub_store()
    if sub_id not in store["subscriptions"]:
        return
    store["subscriptions"][sub_id]["last_text"] = text
    save_whitesub_store(store)


def find_whitesub_subscription_by_token(token):
    store = get_whitesub_store()
    for sub_id, sub in store["subscriptions"].items():
        if sub["token"] == token:
            return sub_id, sub
    return None, None


def ensure_self_signed_cert():
    """Самоподписанный сертификат для /sub - клиент (olcbox) подключается с
    allowInsecureRequests=true и не проверяет hostname/issuer, так что тут
    важен только сам факт TLS (шифрование канала), а не доверенный CA."""
    if os.path.exists(SUB_CERT_FILE) and os.path.exists(SUB_KEY_FILE):
        return
    os.makedirs(SUB_CERT_DIR, exist_ok=True)
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-nodes", "-days", "3650",
        "-keyout", SUB_KEY_FILE, "-out", SUB_CERT_FILE,
        "-subj", "/CN=whitelite-sub",
    ], check=True, capture_output=True, text=True)


class SubscriptionRequestHandler(BaseHTTPRequestHandler):
    """Отдаёт последнюю сформированную подписку по адресу /sub/<token>, где
    token однозначно определяет одну из (возможно нескольких) подписок.
    Любой другой путь или неизвестный токен - 404, чтобы не подсказывать
    сканерам, что путь вообще существует."""

    protocol_version = "HTTP/1.1"  # длина тела всегда явная (Content-Length),
    # а не полагается на "конец = закрытие соединения" как в HTTP/1.0

    def send_empty(self, code):
        # под HTTP/1.1 без Content-Length клиент не понимает, где кончается
        # ответ, и виснет в ожидании (сервер держит keep-alive) - явный 0
        # обязателен даже для пустого тела.
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        prefix = "/sub/"
        if not self.path.startswith(prefix):
            self.send_empty(404)
            return

        token = self.path[len(prefix):]
        _, sub = find_whitesub_subscription_by_token(token)
        if sub is None or not sub.get("last_text"):
            self.send_empty(404)
            return

        body = sub["last_text"].encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # не шумим в логи бота на случайные сканы порта


class SubscriptionHTTPSServer(ThreadingHTTPServer):
    def shutdown_request(self, request):
        # ssl.SSLSocket.close() не шлёт TLS close_notify - строгие клиенты
        # (OkHttp/URLSession) читают это как оборванное соединение. unwrap()
        # делает штатное TLS-прощание перед закрытием сокета.
        try:
            request.unwrap()
        except Exception:
            pass
        super().shutdown_request(request)


def start_subscription_server():
    ensure_self_signed_cert()
    server = SubscriptionHTTPSServer(("0.0.0.0", SUB_HTTPS_PORT), SubscriptionRequestHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=SUB_CERT_FILE, keyfile=SUB_KEY_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def whitesub_link_for(sub_id, sub):
    host = PUBLIC_HOST.strip()
    if not host:
        return None
    return f"https://{host}:{SUB_HTTPS_PORT}/sub/{sub['token']}"


def get_jitsi_denylist():
    data = load_json_file(JITSI_DENYLIST_FILE, None)
    if data is None:
        save_json_file(JITSI_DENYLIST_FILE, {"hosts": SEED_JITSI_DENYLIST})
        return list(SEED_JITSI_DENYLIST)
    return data.get("hosts", [])


def add_to_jitsi_denylist(host):
    hosts = get_jitsi_denylist()
    if host not in hosts:
        hosts.append(host)
        save_json_file(JITSI_DENYLIST_FILE, {"hosts": hosts})


def get_default_jitsi_instance():
    return load_json_file(DEFAULT_JITSI_FILE, {}).get("host", OLCRTC_JITSI_INSTANCE)


def set_default_jitsi_instance(host):
    save_json_file(DEFAULT_JITSI_FILE, {"host": host})


def sanitize_alias(text):
    """Убирает символы, ломающие Markdown (бэктики/звёздочки/подчёркивания/скобки) и переносы строк."""
    alias = re.sub(r'[`*_\[\]\n\r]', ' ', text)
    alias = re.sub(r'\s+', ' ', alias).strip()
    return alias[:40] if alias else "(без имени)"


def sanitize_jitsi_host(raw):
    """Возвращает (host, error). error is None если всё ок."""
    host = raw.strip()
    host = re.sub(r'^https?://', '', host)
    host = host.split('/', 1)[0]  # отбросить путь, если вставили ссылку на комнату

    if not JITSI_HOST_RE.match(host):
        return None, f"⛔ Некорректный домен Jitsi-сервера: `{host}`"

    return host, None


def send_long_message(chat_id, text, parse_mode=None):
    """Шлёт текст одним сообщением, а если он длиннее лимита телеграма - режет по строкам."""
    lines = text.split("\n")
    chunk = ""
    for line in lines:
        candidate = f"{chunk}\n{line}" if chunk else line
        if len(candidate) > TELEGRAM_MSG_LIMIT:
            if chunk:
                bot.send_message(chat_id, chunk, parse_mode=parse_mode)
            chunk = line
        else:
            chunk = candidate
    if chunk:
        bot.send_message(chat_id, chunk, parse_mode=parse_mode)


def is_bare_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


JITSI_ANON_CHECK_TIMEOUT = 4   # сек: если процесс не упал раньше - анонимный вход прошёл
JITSI_ANON_CHECK_WORKERS = 8   # конкурентность, без фанатизма


def check_jitsi_anonymous_login(host):
    """Реально пробует зайти в комнату через настоящий olcrtc (образ olcrtc-server:latest) -
    это ловит случаи вроде 'server does not advertise anonymous XMPP login', которые не видны
    через обычный HTTP GET. Если анонимный вход проходит, процесс успешно джойнится и висит,
    ожидая клиента (не завершается сам) - поэтому упирается в таймаут, и это сигнал "работает".
    Если он падает раньше таймаута - что-то не так (в т.ч. анонимный логин недоступен)."""
    container_name = f"olcrtc-probe-{uuid.uuid4().hex[:8]}"
    room_id = f"https://{host}/probe-{uuid.uuid4().hex[:8]}"
    enc_key = os.urandom(32).hex()

    try:
        subprocess.run(
            [
                "docker", "run", "--rm",
                "--name", container_name,
                "--network", "host",
                "-e", f"ROOM_ID={room_id}",
                "-e", f"ENC_KEY={enc_key}",
                "-e", "PROVIDER=jitsi",
                "-e", "TRANSPORT=datachannel",
                OLCRTC_IMAGE,
            ],
            capture_output=True, text=True, timeout=JITSI_ANON_CHECK_TIMEOUT,
        )
        return False  # завершился раньше времени сам - что-то не так
    except subprocess.TimeoutExpired:
        return True
    except Exception:
        return False
    finally:
        subprocess.run(["docker", "kill", container_name], capture_output=True, text=True)
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True)


def filter_by_anonymous_login(hosts):
    """Прогоняет кандидатов через check_jitsi_anonymous_login параллельно, отсекая тех,
    кто не проходит реальный XMPP/MUC-джойн (проходят HTTP-пробы, но не годятся для туннеля).
    Провалившихся хостов сразу помечает как проблемные (denylist) - в следующий раз их уже
    не нужно будет перепроверять этой дорогой проверкой, они отсеются на дешёвом этапе."""
    good = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=JITSI_ANON_CHECK_WORKERS) as pool:
        futures = {pool.submit(check_jitsi_anonymous_login, h): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            if future.result():
                good.append(host)
            else:
                add_to_jitsi_denylist(host)
    return good


def fetch_jitsi_candidates(check_anonymous_login=True):
    """Тянет список кандидатов, отбрасывая голые IP и хосты из denylist. Если
    check_anonymous_login=True (по умолчанию), дополнительно прогоняет реальную проверку
    анонимного XMPP-логина (check_jitsi_anonymous_login) - её можно отключить флагом
    -checkoff, если нужен быстрый скан без этой дорогой проверки.
    Голые IP: реальный Jitsi-коннект идёт через TLS с проверкой сертификата по
    hostname/SNI, а у сертификата нет IP SAN'ов - такие хосты проходят HTTP-пробы,
    но никогда не работают как туннель. Denylist - хосты, провалившие check_jitsi_anonymous_login
    ранее (помечаются туда автоматически) или добавленные вручную."""
    resp = requests.get(JITSI_LIST_URL, timeout=10)
    resp.raise_for_status()
    denylist = set(get_jitsi_denylist())
    hosts = []
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and not is_bare_ip(line) and line not in denylist:
            hosts.append(line)
    if check_anonymous_login:
        hosts = filter_by_anonymous_login(hosts)
    return hosts


def probe_jitsi_host(host):
    start = time.monotonic()
    try:
        r = requests.get(f"https://{host}/", timeout=JITSI_SCAN_TIMEOUT, verify=False, allow_redirects=True)
        elapsed = time.monotonic() - start
        if r.status_code < 500:
            return host, elapsed, None
        return host, elapsed, f"HTTP {r.status_code}"
    except Exception as e:
        return host, time.monotonic() - start, str(e)


def scan_best_jitsi(progress_cb, hosts=None, check_anonymous_login=True):
    """Пробегается по списку кандидатов, отчитывается через progress_cb(done, total, found).
    Если hosts не передан, тянет список сам (для одиночного вызова -best_ms)."""
    if hosts is None:
        hosts = fetch_jitsi_candidates(check_anonymous_login=check_anonymous_login)
    total = len(hosts)
    results = []
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=JITSI_SCAN_WORKERS) as pool:
        futures = [pool.submit(probe_jitsi_host, h) for h in hosts]
        for future in concurrent.futures.as_completed(futures):
            host, elapsed, err = future.result()
            done += 1
            if err is None:
                results.append((host, elapsed))
            progress_cb(done, total, len(results))

    results.sort(key=lambda x: x[1])
    return results, total


def probe_jitsi_speed(host):
    """Качает данные с хоста повторными запросами (keep-alive) до JITSI_SPEED_TARGET_BYTES
    или до защитного тайм-аута, если сервер слишком медленный/страница слишком маленькая.
    Ошибка отдельной итерации (например таймаут ближе к границе SAFETY) останавливает цикл,
    но не отбрасывает уже накопленные байты. Возвращает (host, mbps, error)."""
    start = time.monotonic()
    total_bytes = 0
    first_attempt_error = None

    session = requests.Session()
    session.verify = False

    while total_bytes < JITSI_SPEED_TARGET_BYTES:
        elapsed = time.monotonic() - start
        remaining = JITSI_SPEED_SAFETY_SECONDS - elapsed
        if remaining <= 0:
            break

        try:
            with session.get(
                f"https://{host}/",
                timeout=(JITSI_SPEED_CONNECT_TIMEOUT, remaining),
                stream=True,
            ) as r:
                if r.status_code >= 500:
                    if total_bytes == 0:
                        return host, 0.0, f"HTTP {r.status_code}"
                    break
                got_any = False
                for chunk in r.iter_content(chunk_size=65536):
                    if not chunk:
                        break
                    got_any = True
                    total_bytes += len(chunk)
                    elapsed = time.monotonic() - start
                    if elapsed >= JITSI_SPEED_SAFETY_SECONDS or total_bytes >= JITSI_SPEED_TARGET_BYTES:
                        break
                if not got_any:
                    break  # пустой ответ, нет смысла зацикливаться дальше
        except Exception as e:
            if total_bytes == 0:
                first_attempt_error = str(e)
            break  # ошибка в конкретной итерации - используем то, что уже накопили

    elapsed = time.monotonic() - start
    if total_bytes == 0 or elapsed <= 0:
        return host, 0.0, first_attempt_error or "нет данных"

    mbps = (total_bytes * 8) / elapsed / 1_000_000
    return host, mbps, None


def scan_best_long_jitsi(progress_cb, hosts=None, check_anonymous_login=True):
    """Как scan_best_jitsi, но ранжирует по реальной скорости скачивания (Mbps, >=20МБ на хост), не по задержке.
    Если hosts не передан, тянет список сам (для одиночного вызова -best_mb)."""
    if hosts is None:
        hosts = fetch_jitsi_candidates(check_anonymous_login=check_anonymous_login)
    total = len(hosts)
    results = []
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=JITSI_SPEED_WORKERS) as pool:
        futures = [pool.submit(probe_jitsi_speed, h) for h in hosts]
        for future in concurrent.futures.as_completed(futures):
            host, mbps, err = future.result()
            done += 1
            if err is None and mbps > 0:
                results.append((host, mbps))
            progress_cb(done, total, len(results))

    results.sort(key=lambda x: x[1], reverse=True)
    return results, total


class _Ns:
    """Заглушка объекта-контейнера атрибутов - чтобы не тащить лишний импорт
    types/SimpleNamespace ради пары полей."""
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeMessage:
    """Подделка telebot.types.Message для переиспользования уже существующих
    обработчиков команд из callback-кнопок меню - один код путь что для
    текстовой команды, что для кнопки, без дублирования логики."""
    def __init__(self, chat_id, user_id, text, message_id):
        self.chat = _Ns(id=chat_id)
        self.from_user = _Ns(id=user_id)
        self.text = text
        self.message_id = message_id
        self.reply_to_message = None


def main_menu_keyboard():
    kb = telebot.types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        telebot.types.InlineKeyboardButton("🆕 Новый OpenVPN", callback_data="cmd:new"),
        telebot.types.InlineKeyboardButton("🌐 White (по умолчанию)", callback_data="cmd:white"),
    )
    kb.add(
        telebot.types.InlineKeyboardButton("🚀 White: авто-подбор", callback_data="cmd:white_best_all"),
    )
    kb.add(
        telebot.types.InlineKeyboardButton("📦 Whitesub", callback_data="cmd:whitesub_menu"),
    )
    kb.add(
        telebot.types.InlineKeyboardButton("📋 Список", callback_data="cmd:list"),
        telebot.types.InlineKeyboardButton("📊 Мониторинг", callback_data="cmd:monitor"),
    )
    return kb


def whitesub_submenu_keyboard():
    kb = telebot.types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        telebot.types.InlineKeyboardButton("🆕 Новая подписка", callback_data="cmd:whitesub_new_menu"),
        telebot.types.InlineKeyboardButton("📚 Список", callback_data="cmd:whitesub_list"),
    )
    kb.add(
        telebot.types.InlineKeyboardButton("⬅️ Назад", callback_data="cmd:menu_main"),
    )
    return kb


def whitesub_new_submenu_keyboard():
    kb = telebot.types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        telebot.types.InlineKeyboardButton("➕", callback_data="cmd:whitesub_new_create"),
        telebot.types.InlineKeyboardButton("⚙️ Конфигурация", callback_data="cmd:whitesub_config"),
    )
    kb.add(
        telebot.types.InlineKeyboardButton("⬅️ Назад", callback_data="cmd:whitesub_menu"),
    )
    return kb


@bot.message_handler(commands=['start'])
def handle_start(message):
    bot.reply_to(
        message,
        "🔐 *VPN Бот*\n\n"
        "Привет! Я помогу получить конфиг для подключения к VPN.\n\n"
        "Жми на кнопки ниже или пользуйся командами напрямую (`/menu`, чтобы вызвать кнопки ещё раз):\n\n"
        "*/new* — сгенерировать новый профиль и получить `.ovpn` файл\n"
        "*/white* `[jitsi-сервер]` — поднять запасной туннель через белые списки (Jitsi/WebRTC), для случаев когда обычный VPN режут\n"
        f"  по умолчанию `{get_default_jitsi_instance()}`, можно указать свой: `/white meet.small-dm.ru`\n"
        "*/white* `-best_ms` — просканировать публичный список Jitsi-серверов и поднять туннель на сервере с наименьшей задержкой\n"
        "*/white* `-best_mb` — то же самое, но выбор по реальной скорости скачивания (Mbps, тест на 20+ МБ), а не по задержке — дольше, но точнее\n"
        "*/white* `-best_all` — проводит оба теста и считает комбинированный балл по местам в каждом (1 место = -1 балл, N место = -N баллов, старт у всех N+1; место по скорости считается с двойным весом)\n"
        "  добавь `-test` к любому из `-best_ms` / `-best_mb` / `-best_all` (например `/white -best_ms -test`), чтобы только увидеть результаты скана без подъёма туннеля\n"
        "  добавь `-checkoff`, чтобы отключить реальную проверку анонимного XMPP-логина (быстрее, но без гарантии, что домен реально годится для туннеля)\n"
        "*/white* `-default <домен>` — задать домен по умолчанию для обычного `/white` (например `/white -default meet.small-dm.ru`)\n"
        "*/monitor* — статистика клиентов и загрузка канала\n"
        "*/list* — список всех клиентов: OpenVPN и White отдельно, внутри групп по убыванию трафика/активности\n"
        "  пришли имя конфига из списка (например `user_cd89c7` или `olcrtc-68518b35`), чтобы получить его заново — ответь на это сообщение текстом, чтобы задать имя, видимое в /list\n"
        "*/whitesub* `-setup [N]` — прогоняет оба скана (как `-best_all -test`), присылает полный список и ждёт от тебя номера позиций, которые реально работают в твоей сети — ответь на сообщение-приглашение номерами через запятую/пробел, сохранит лучшие N из подтверждённых как пул (по умолчанию N=5), туннели пока не поднимает; добавь `-checkoff`, чтобы пропустить проверку анонимного XMPP-логина\n"
        "*/whitesub* `[N]` — поднимает N туннелей из сохранённого пула (по умолчанию N=5) в *активную* подписку, одним сообщением присылает все её конфиги, затем файл и `https` ссылку (для импорта в olcbox: добавление конфигурации → импорт из файла или ввод ссылки, для ссылки нужно включить `Allow insecure requests` - сертификат самоподписанный). Ответь на сводное сообщение текстом, чтобы переименовать подписку\n"
        "*/whitesub* `-new [имя]` — создаёт новую подписку со своим id и уникальной ссылкой, делает её активной\n"
        "*/whitesub* `-list` — список всех подписок с их id/именем/ссылкой (★ - активная)\n"
        "*/whitesub* `-use <id>` — переключить активную подписку\n"
        "*/start* — показать это сообщение\n"
        "*/menu* — показать кнопки меню",
        parse_mode="Markdown",
        reply_markup=main_menu_keyboard()
    )


@bot.message_handler(commands=['menu'])
def handle_menu(message):
    if not is_admin(message):
        return
    bot.reply_to(message, "📋 Меню:", reply_markup=main_menu_keyboard())


@bot.callback_query_handler(func=lambda c: c.data.startswith("cmd:"))
def handle_menu_callback(call):
    bot.answer_callback_query(call.id)
    if call.from_user.id != ADMIN_TELEGRAM_ID:
        return  # молча игнорируем не-админов

    action = call.data[len("cmd:"):]
    fake = FakeMessage(call.message.chat.id, call.from_user.id, "", call.message.message_id)

    try:
        if action == "whitesub_menu":
            bot.edit_message_reply_markup(
                call.message.chat.id, call.message.message_id,
                reply_markup=whitesub_submenu_keyboard()
            )
            return
        elif action == "menu_main":
            bot.edit_message_reply_markup(
                call.message.chat.id, call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
            return
        elif action == "whitesub_new_menu":
            bot.edit_message_reply_markup(
                call.message.chat.id, call.message.message_id,
                reply_markup=whitesub_new_submenu_keyboard()
            )
            return
        elif action == "whitesub_new_create":
            handle_whitesub_new_create(fake)
        elif action == "whitesub_config":
            send_whitesub_config(call.message.chat.id)
        elif action == "whitesub_config_check":
            pool = get_whitesub_pool()
            if not pool:
                bot.send_message(call.message.chat.id, "Конфигурация пуста, нечего проверять.")
                return
            status = bot.send_message(
                call.message.chat.id,
                f"⏳ Проверяю анонимный вход для {len(pool)} серверов "
                f"(до {JITSI_ANON_CHECK_TIMEOUT}с на сервер, параллельно)..."
            )
            recheck_whitesub_pool_anonymous_login()
            bot.delete_message(call.message.chat.id, status.message_id)
            send_whitesub_config(call.message.chat.id)
        elif action == "whitesub_config_reset":
            bot.edit_message_text(
                "⚠️ Точно стереть текущую конфигурацию серверов и пересканировать с нуля?",
                call.message.chat.id, call.message.message_id,
                reply_markup=whitesub_config_reset_confirm_keyboard()
            )
            return
        elif action == "whitesub_config_reset_confirm":
            fake.text = f"/whitesub -setup {WHITESUB_DEFAULT_COUNT}"
            handle_whitesub(fake)
        elif action == "new":
            handle_new_vpn(fake)
        elif action == "white":
            fake.text = "/white"
            handle_white(fake)
        elif action == "white_best_all":
            fake.text = "/white -best_all"
            handle_white(fake)
        elif action == "whitesub_list":
            fake.text = "/whitesub -list"
            handle_whitesub(fake)
        elif action == "list":
            handle_list(fake)
        elif action == "monitor":
            handle_monitor(fake)
    except Exception as e:
        try:
            bot.send_message(call.message.chat.id, f"❌ Ошибка: {e}")
        except Exception:
            pass


@bot.callback_query_handler(func=lambda c: c.data.startswith("wsub_use:"))
def handle_wsub_use_callback(call):
    bot.answer_callback_query(call.id)
    if call.from_user.id != ADMIN_TELEGRAM_ID:
        return

    sub_id = call.data[len("wsub_use:"):]
    fake = FakeMessage(call.message.chat.id, call.from_user.id, "", call.message.message_id)
    handle_whitesub_use(fake, sub_id)


@bot.message_handler(commands=['new'])
def handle_new_vpn(message):
    # Генерируем случайное имя
    client_name = f"user_{uuid.uuid4().hex[:6]}"
    msg = bot.reply_to(message, f"⏳ Генерирую конфиг для `{client_name}`... Подождите немного.")

    try:
        # 1. Создаем сертификат (без пароля - 'nopass')
        subprocess.run([
            "docker", "exec", VPN_CONTAINER_NAME,
            "easyrsa", "build-client-full", client_name, "nopass"
        ], check=True)

        # 2. Получаем готовый .ovpn файл
        result = subprocess.run([
            "docker", "exec", VPN_CONTAINER_NAME,
            "ovpn_getclient", client_name
        ], capture_output=True, text=True, check=True)

        # 3. Сохраняем временно и отправляем
        file_path = f"{client_name}.ovpn"
        with open(file_path, "w") as f:
            f.write(result.stdout)

        with open(file_path, "rb") as f:
            sent = bot.send_document(
                message.chat.id,
                f,
                caption=(
                    f"✅ Готово!\n👤 Профиль: `{client_name}`\n\n"
                    "Ответь на это сообщение текстом, чтобы задать имя, видимое в /list."
                )
            )
        pending_rename[sent.message_id] = client_name

        # Удаляем временный файл
        os.remove(file_path)
        bot.delete_message(message.chat.id, msg.message_id)

    except Exception as e:
        bot.edit_message_text(f"❌ Ошибка при генерации: {str(e)}", message.chat.id, msg.message_id)


def create_white_tunnel(jitsi_instance, source="white"):
    """Создаёт один white-туннель: контейнер + сохранённые метаданные.
    source помечает происхождение (обычный /white vs группа /whitesub -setup),
    чтобы потом можно было выгрузить именно свою группу профилей.
    Бросает исключение при ошибке - вызывающий код решает, как её показать."""
    room_id = f"https://{jitsi_instance}/olcrtc-{uuid.uuid4().hex[:10]}"
    enc_key = os.urandom(32).hex()
    container_name = f"olcrtc-{uuid.uuid4().hex[:8]}"

    subprocess.run([
        "docker", "run", "-d",
        "--name", container_name,
        "--network", "host",
        "--restart", "unless-stopped",
        "-e", f"ROOM_ID={room_id}",
        "-e", f"ENC_KEY={enc_key}",
        "-e", "PROVIDER=jitsi",
        "-e", "TRANSPORT=datachannel",
        OLCRTC_IMAGE,
    ], check=True, capture_output=True, text=True)

    uri = f"olcrtc://jitsi?datachannel@{room_id}#{enc_key}${container_name}"

    save_white_config(container_name, {
        "jitsi_instance": jitsi_instance,
        "room_id": room_id,
        "enc_key": enc_key,
        "uri": uri,
        "created_at": time.time(),
        "source": source,
    })
    return container_name, room_id, uri


def announce_white_tunnel(chat_id, jitsi_instance, container_name, room_id, uri):
    """Шлёт QR+инфо для уже созданного туннеля и регистрирует его для переименования по reply."""
    qr_buf = BytesIO()
    qrcode.make(uri).save(qr_buf, format="PNG")
    qr_buf.seek(0)

    sent = bot.send_photo(
        chat_id,
        qr_buf,
        caption=(
            "✅ Белый конфиг готов\n"
            f"🌐 Jitsi: `{jitsi_instance}`\n"
            f"🏷 Контейнер: `{container_name}`\n"
            f"🚪 Комната: `{room_id}`\n\n"
            "Импортируй QR в olcbox (Android) или используй строку:\n"
            f"`{uri}`\n\n"
            "Скачать olcbox: https://github.com/alananisimov/olcbox/releases/latest\n\n"
            "Ответь на это сообщение текстом, чтобы задать имя, видимое в /list."
        ),
        parse_mode="Markdown"
    )
    pending_rename[sent.message_id] = container_name


def deploy_white_tunnel(chat_id, status_message_id, jitsi_instance):
    try:
        container_name, room_id, uri = create_white_tunnel(jitsi_instance)
        announce_white_tunnel(chat_id, jitsi_instance, container_name, room_id, uri)
        bot.delete_message(chat_id, status_message_id)

    except subprocess.CalledProcessError as e:
        bot.edit_message_text(f"❌ Ошибка docker: {e.stderr}", chat_id, status_message_id)
    except Exception as e:
        bot.edit_message_text(f"❌ Ошибка при генерации: {str(e)}", chat_id, status_message_id)


@bot.message_handler(commands=['white'])
def handle_white(message):
    if not is_admin(message):
        bot.reply_to(message, "⛔ Команда доступна только администратору.")
        return

    tokens = message.text.split()[1:]  # всё после /white, в любом порядке
    flags = {t for t in tokens if t.startswith('-')}
    non_flags = [t for t in tokens if not t.startswith('-')]

    unknown = flags - KNOWN_WHITE_FLAGS
    if unknown:
        bot.reply_to(message, f"⛔ Неизвестный аргумент: {', '.join(sorted(unknown))}")
        return

    mode_flags = flags & {"-best_ms", "-best_mb", "-best_all", "-default"}
    if len(mode_flags) > 1:
        bot.reply_to(message, f"⛔ Нельзя указать одновременно {', '.join(sorted(mode_flags))}.")
        return

    dry_run = "-test" in flags
    check_anonymous_login = "-checkoff" not in flags

    if "-best_ms" in flags:
        handle_white_best(message, dry_run=dry_run, check_anonymous_login=check_anonymous_login)
        return

    if "-best_mb" in flags:
        handle_white_best_long(message, dry_run=dry_run, check_anonymous_login=check_anonymous_login)
        return

    if "-best_all" in flags:
        handle_white_best_all(message, dry_run=dry_run, check_anonymous_login=check_anonymous_login)
        return

    if "-default" in flags:
        if not non_flags:
            bot.reply_to(message, "⛔ Укажи домен: `/white -default meet.example.org`", parse_mode="Markdown")
            return
        host, error = sanitize_jitsi_host(non_flags[0])
        if error:
            bot.reply_to(message, error, parse_mode="Markdown")
            return
        set_default_jitsi_instance(host)
        bot.reply_to(message, f"✅ Домен по умолчанию для `/white` теперь `{host}`", parse_mode="Markdown")
        return

    if dry_run:
        bot.reply_to(message, "⛔ -test работает только вместе с -best_ms, -best_mb или -best_all.")
        return

    if not check_anonymous_login:
        bot.reply_to(message, "⛔ -checkoff работает только вместе с -best_ms, -best_mb или -best_all.")
        return

    if non_flags:
        jitsi_instance, error = sanitize_jitsi_host(non_flags[0])
        if error:
            bot.reply_to(message, error, parse_mode="Markdown")
            return
    else:
        jitsi_instance = get_default_jitsi_instance()

    msg = bot.reply_to(message, f"⏳ Поднимаю новый туннель через белые списки (Jitsi: {jitsi_instance})... Подождите немного.")
    deploy_white_tunnel(message.chat.id, msg.message_id, jitsi_instance)


def format_results_list(results, unit):
    lines = []
    for i, (host, value) in enumerate(results, start=1):
        if unit == "ms":
            lines.append(f"{i}. `{host}` — {value * 1000:.0f} мс")
        else:
            lines.append(f"{i}. `{host}` — {value:.1f} Mbps")
    return "\n".join(lines)


BEST_ALL_SPEED_WEIGHT = 2  # баллы за место в speed-тесте учитываются с этим множителем


def compute_combined_scores(hosts, latency_results, speed_results):
    """Балльная система: у каждого хоста изначально len(hosts)+1 баллов.
    За каждый тест вычитается место хоста в этом тесте (1 место = -1 балл, N место = -N баллов),
    место в speed-тесте умножается на BEST_ALL_SPEED_WEIGHT.
    Хост, не ответивший в тесте, получает худшее возможное место (len(hosts)+1) в этом тесте.
    Возвращает список (host, score, latency_rank, latency_sec, speed_rank, mbps),
    отсортированный по score по убыванию (выше = лучше)."""
    n = len(hosts)
    worst_rank = n + 1
    initial_score = worst_rank

    latency_rank = {host: i for i, (host, _) in enumerate(latency_results, start=1)}
    latency_value = dict(latency_results)
    speed_rank = {host: i for i, (host, _) in enumerate(speed_results, start=1)}
    speed_value = dict(speed_results)

    combined = []
    for host in hosts:
        lr = latency_rank.get(host, worst_rank)
        sr = speed_rank.get(host, worst_rank)
        score = initial_score - lr - (BEST_ALL_SPEED_WEIGHT * sr)
        combined.append((
            host, score,
            latency_rank.get(host), latency_value.get(host),
            speed_rank.get(host), speed_value.get(host),
        ))

    combined.sort(key=lambda x: x[1], reverse=True)
    return combined


def format_combined_results_list(combined):
    lines = []
    for i, (host, score, lr, lv, sr, sv) in enumerate(combined, start=1):
        ms_part = f"{lv * 1000:.0f} мс (#{lr})" if lr is not None else "нет ответа"
        mbps_part = f"{sv:.1f} Mbps (#{sr})" if sr is not None else "нет ответа"
        lines.append(f"{i}. `{host}` — счёт {score}: {ms_part} / {mbps_part}")
    return "\n".join(lines)


def handle_white_best(message, dry_run=False, check_anonymous_login=True):
    msg = bot.reply_to(message, "🔍 Получаю список Jitsi-серверов...")
    last_edit = {"t": 0.0}

    def progress_cb(done, total, found):
        now = time.monotonic()
        if done != total and now - last_edit["t"] < JITSI_SCAN_PROGRESS_MIN_INTERVAL:
            return
        last_edit["t"] = now
        try:
            bot.edit_message_text(
                f"🔍 Сканирую Jitsi-серверы: {done}/{total} (осталось {total - done}), рабочих найдено: {found}",
                message.chat.id, msg.message_id
            )
        except Exception:
            pass  # skip flood-control edit errors, not critical

    try:
        results, total = scan_best_jitsi(progress_cb, check_anonymous_login=check_anonymous_login)
    except Exception as e:
        bot.edit_message_text(f"❌ Не удалось получить список серверов: {e}", message.chat.id, msg.message_id)
        return

    if not results:
        bot.edit_message_text(
            f"❌ Просканировано {total} серверов, ни один не ответил из этой сети.",
            message.chat.id, msg.message_id
        )
        return

    best_host, best_latency = results[0]
    bot.edit_message_text(
        f"✅ Просканировано {total}, рабочих: {len(results)}\n"
        f"🏆 Лучший: `{best_host}` ({best_latency * 1000:.0f} мс)\n\n"
        + ("🧪 Режим -test: туннель не поднимается." if dry_run else "⏳ Поднимаю туннель на нём..."),
        message.chat.id, msg.message_id, parse_mode="Markdown"
    )

    send_long_message(
        message.chat.id,
        "📋 *Полный список по задержке:*\n" + format_results_list(results, "ms"),
        parse_mode="Markdown"
    )

    if not dry_run:
        deploy_white_tunnel(message.chat.id, msg.message_id, best_host)


def handle_white_best_long(message, dry_run=False, check_anonymous_login=True):
    msg = bot.reply_to(message, "🚀 Получаю список Jitsi-серверов (тест на 20+ МБ на хост, может занять пару минут)...")
    last_edit = {"t": 0.0}

    def progress_cb(done, total, found):
        now = time.monotonic()
        if done != total and now - last_edit["t"] < JITSI_SCAN_PROGRESS_MIN_INTERVAL:
            return
        last_edit["t"] = now
        try:
            bot.edit_message_text(
                f"🚀 Меряю скорость Jitsi-серверов: {done}/{total} (осталось {total - done}), рабочих найдено: {found}",
                message.chat.id, msg.message_id
            )
        except Exception:
            pass  # skip flood-control edit errors, not critical

    try:
        results, total = scan_best_long_jitsi(progress_cb, check_anonymous_login=check_anonymous_login)
    except Exception as e:
        bot.edit_message_text(f"❌ Не удалось получить список серверов: {e}", message.chat.id, msg.message_id)
        return

    if not results:
        bot.edit_message_text(
            f"❌ Просканировано {total} серверов, ни один не отдал данные из этой сети.",
            message.chat.id, msg.message_id
        )
        return

    best_host, best_mbps = results[0]
    bot.edit_message_text(
        f"✅ Просканировано {total}, рабочих: {len(results)}\n"
        f"🏆 Лучший: `{best_host}` ({best_mbps:.1f} Mbps)\n"
        "_(скорость до веб-морды Jitsi, не гарантирует скорость видеомоста)_\n\n"
        + ("🧪 Режим -test: туннель не поднимается." if dry_run else "⏳ Поднимаю туннель на нём..."),
        message.chat.id, msg.message_id, parse_mode="Markdown"
    )

    send_long_message(
        message.chat.id,
        "📋 *Полный список по скорости:*\n" + format_results_list(results, "mbps"),
        parse_mode="Markdown"
    )

    if not dry_run:
        deploy_white_tunnel(message.chat.id, msg.message_id, best_host)


def handle_white_best_all(message, dry_run=False, check_anonymous_login=True):
    msg = bot.reply_to(message, "🧮 Получаю список Jitsi-серверов (оба теста, займёт пару минут)...")
    last_edit = {"t": 0.0}

    try:
        hosts = fetch_jitsi_candidates(check_anonymous_login=check_anonymous_login)
    except Exception as e:
        bot.edit_message_text(f"❌ Не удалось получить список серверов: {e}", message.chat.id, msg.message_id)
        return

    def make_progress_cb(stage_label):
        def progress_cb(done, total, found):
            now = time.monotonic()
            if done != total and now - last_edit["t"] < JITSI_SCAN_PROGRESS_MIN_INTERVAL:
                return
            last_edit["t"] = now
            try:
                bot.edit_message_text(
                    f"🧮 {stage_label}: {done}/{total} (осталось {total - done}), рабочих найдено: {found}",
                    message.chat.id, msg.message_id
                )
            except Exception:
                pass  # skip flood-control edit errors, not critical
        return progress_cb

    try:
        latency_results, total = scan_best_jitsi(make_progress_cb("Этап 1/2, задержка"), hosts=hosts)
        speed_results, _ = scan_best_long_jitsi(make_progress_cb("Этап 2/2, скорость"), hosts=hosts)
    except Exception as e:
        bot.edit_message_text(f"❌ Ошибка во время сканирования: {e}", message.chat.id, msg.message_id)
        return

    if not latency_results and not speed_results:
        bot.edit_message_text(
            f"❌ Просканировано {total} серверов, ни один не ответил ни в одном из тестов.",
            message.chat.id, msg.message_id
        )
        return

    combined = compute_combined_scores(hosts, latency_results, speed_results)
    best_host, best_score, best_lr, best_lv, best_sr, best_sv = combined[0]

    ms_part = f"{best_lv * 1000:.0f} мс (#{best_lr})" if best_lr is not None else "нет ответа"
    mbps_part = f"{best_sv:.1f} Mbps (#{best_sr})" if best_sr is not None else "нет ответа"

    bot.edit_message_text(
        f"✅ Просканировано {total}\n"
        f"🏆 Лучший: `{best_host}` — счёт {best_score}\n"
        f"   задержка: {ms_part}\n"
        f"   скорость: {mbps_part}\n\n"
        + ("🧪 Режим -test: туннель не поднимается." if dry_run else "⏳ Поднимаю туннель на нём..."),
        message.chat.id, msg.message_id, parse_mode="Markdown"
    )

    send_long_message(
        message.chat.id,
        "📋 *Полный список (комбинированный балл):*\n" + format_combined_results_list(combined),
        parse_mode="Markdown"
    )

    if not dry_run:
        deploy_white_tunnel(message.chat.id, msg.message_id, best_host)


@bot.message_handler(commands=['whitesub'])
def handle_whitesub(message):
    if not is_admin(message):
        bot.reply_to(message, "⛔ Команда доступна только администратору.")
        return

    tokens = message.text.split()[1:]
    flags = {t for t in tokens if t.startswith('-')}
    words = [t for t in tokens if not t.startswith('-')]

    unknown = flags - {"-setup", "-checkoff", "-new", "-list", "-use"}
    if unknown:
        bot.reply_to(message, f"⛔ Неизвестный аргумент: {', '.join(sorted(unknown))}")
        return

    exclusive = flags & {"-setup", "-new", "-list", "-use"}
    if len(exclusive) > 1:
        bot.reply_to(message, f"⛔ Нельзя указать одновременно {', '.join(sorted(exclusive))}.")
        return

    if "-checkoff" in flags and "-setup" not in flags:
        bot.reply_to(message, "⛔ -checkoff работает только вместе с -setup.")
        return

    if "-new" in flags:
        name = sanitize_alias(" ".join(words)) if words else "WhiteLite"
        handle_whitesub_new(message, name)
        return

    if "-list" in flags:
        handle_whitesub_list(message)
        return

    if "-use" in flags:
        if not words:
            bot.reply_to(message, "⛔ Укажи id подписки: `/whitesub -use wsub-xxxxxxxx`", parse_mode="Markdown")
            return
        handle_whitesub_use(message, words[0])
        return

    count = WHITESUB_DEFAULT_COUNT
    if words:
        try:
            count = int(words[0])
        except ValueError:
            bot.reply_to(message, "⛔ N должно быть числом, например `/whitesub 10`.", parse_mode="Markdown")
            return

    if not (1 <= count <= WHITESUB_MAX_COUNT):
        bot.reply_to(message, f"⛔ N должно быть от 1 до {WHITESUB_MAX_COUNT}.")
        return

    if "-setup" in flags:
        check_anonymous_login = "-checkoff" not in flags
        handle_whitesub_setup(message, count, check_anonymous_login=check_anonymous_login)
        return

    handle_whitesub_deploy(message, count)


def handle_whitesub_new(message, name):
    sub_id, sub = create_whitesub_subscription(name)
    link = whitesub_link_for(sub_id, sub)
    text = (
        "✅ Новая подписка создана и сделана активной\n"
        f"🏷 Имя: {sub['name']}\n"
        f"🆔 id: `{sub_id}`\n"
    )
    if link:
        text += f"🔗 Ссылка: `{link}`\n"
    text += (
        "\nДальнейшие `/whitesub [N]` наполняют именно её. "
        "Переключиться на другую: `/whitesub -use <id>`, список всех: `/whitesub -list`."
    )
    bot.reply_to(message, text, parse_mode="Markdown")


def handle_whitesub_list(message):
    store = get_whitesub_store()
    if not store["subscriptions"]:
        bot.reply_to(message, "Подписок пока нет. Создай через `/whitesub -new [имя]`.", parse_mode="Markdown")
        return

    active_id = store.get("active_id")
    lines = ["📚 Подписки:"]
    kb = telebot.types.InlineKeyboardMarkup(row_width=1)
    for sub_id, sub in store["subscriptions"].items():
        mark = "★" if sub_id == active_id else "·"
        empty = " (пусто)" if not sub.get("last_text") else ""
        lines.append(f"{mark} `{sub_id}` — {sub['name']}{empty}")
        link = whitesub_link_for(sub_id, sub)
        if link:
            lines.append(f"    `{link}`")
        if sub_id != active_id:
            kb.add(telebot.types.InlineKeyboardButton(
                f"➡️ Сделать активной: {sub['name']}", callback_data=f"wsub_use:{sub_id}"
            ))
    send_long_message(message.chat.id, "\n".join(lines), parse_mode="Markdown")
    if kb.keyboard:
        bot.send_message(message.chat.id, "Переключить активную:", reply_markup=kb)


def handle_whitesub_use(message, sub_id):
    if not set_active_whitesub_subscription(sub_id):
        bot.reply_to(message, f"⛔ Подписка `{sub_id}` не найдена. Смотри `/whitesub -list`.", parse_mode="Markdown")
        return
    _, sub = get_active_whitesub_subscription()
    bot.reply_to(message, f"✅ Активная подписка теперь: {sub['name']} (`{sub_id}`)", parse_mode="Markdown")


WHITESUB_CHECK_EMOJI = {"ok": "✅", "fail": "❌", "skipped": "❔"}


def format_whitesub_config_text():
    pool = get_whitesub_pool()
    lines = ["⚙️ *Конфигурация серверов* (пул для новых подписок):"]
    if not pool:
        lines.append("_пусто_")
    for i, entry in enumerate(pool, 1):
        emoji = WHITESUB_CHECK_EMOJI.get(entry.get("checks"), "❔")
        lines.append(f"{i}. {emoji} `{entry['host']}`")
    lines.append(
        "\n✅ анонимный вход в Jitsi подтверждён · "
        "❌ анонимный вход не прошёл · "
        "❔ не проверялось"
    )
    lines.append(
        "\nОтветь на это сообщение доменом Jitsi-сервера, чтобы добавить его "
        "(пройдёт проверку anon-login).\n"
        "Ответь `-N` (например `-2`), чтобы удалить позицию N."
    )
    return "\n".join(lines)


def whitesub_config_keyboard():
    kb = telebot.types.InlineKeyboardMarkup(row_width=1)
    kb.add(telebot.types.InlineKeyboardButton(
        "🔍 Проверить анонимный вход", callback_data="cmd:whitesub_config_check"
    ))
    kb.add(telebot.types.InlineKeyboardButton("🔄 Настроить с 0", callback_data="cmd:whitesub_config_reset"))
    kb.add(telebot.types.InlineKeyboardButton("⬅️ Назад", callback_data="cmd:whitesub_new_menu"))
    return kb


def recheck_whitesub_pool_anonymous_login():
    """Перепроверяет anon-login для всех хостов пула параллельно и обновляет
    их отметку checks на месте (не трогает denylist - это только пометка
    в самой конфигурации, а не решение о её исключении из будущих сканов)."""
    pool = get_whitesub_pool()
    if not pool:
        return pool

    hosts = [entry["host"] for entry in pool]
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=JITSI_ANON_CHECK_WORKERS) as executor:
        futures = {executor.submit(check_jitsi_anonymous_login, h): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            results[host] = future.result()

    for entry in pool:
        entry["checks"] = "ok" if results.get(entry["host"]) else "fail"
    save_whitesub_pool(pool)
    return pool


def whitesub_config_reset_confirm_keyboard():
    kb = telebot.types.InlineKeyboardMarkup(row_width=1)
    kb.add(telebot.types.InlineKeyboardButton(
        "✅ Да, стереть и пересканировать", callback_data="cmd:whitesub_config_reset_confirm"
    ))
    kb.add(telebot.types.InlineKeyboardButton("❌ Отмена", callback_data="cmd:whitesub_config"))
    return kb


def send_whitesub_config(chat_id):
    sent = bot.send_message(
        chat_id, format_whitesub_config_text(),
        parse_mode="Markdown", reply_markup=whitesub_config_keyboard()
    )
    pending_whitesub_config[sent.message_id] = True


def handle_whitesub_config_reply(message):
    text = message.text.strip()

    m = re.fullmatch(r'-(\d+)', text)
    if m:
        position = int(m.group(1))
        removed = remove_whitesub_pool_at(position)
        if removed is None:
            bot.reply_to(message, f"⛔ Нет позиции {position} в текущем списке.")
        else:
            bot.reply_to(message, f"🗑 Удалено: `{removed['host']}`", parse_mode="Markdown")
        send_whitesub_config(message.chat.id)
        return

    host, error = sanitize_jitsi_host(text)
    if error:
        bot.reply_to(message, error, parse_mode="Markdown")
        return

    status = bot.reply_to(message, f"⏳ Проверяю `{host}`...", parse_mode="Markdown")
    ok = check_jitsi_anonymous_login(host)
    checks = "ok" if ok else "fail"
    add_whitesub_pool_host(host, checks)
    bot.edit_message_text(
        f"{WHITESUB_CHECK_EMOJI[checks]} Добавлено: `{host}`", message.chat.id, status.message_id, parse_mode="Markdown"
    )
    send_whitesub_config(message.chat.id)


def handle_whitesub_new_create(message):
    pool = get_whitesub_pool()
    if not pool:
        bot.reply_to(
            message,
            "❌ Конфигурация пуста. Сначала добавь серверы через ⚙️ Конфигурация.",
            parse_mode="Markdown"
        )
        return
    create_whitesub_subscription()
    handle_whitesub_deploy(message, len(pool))


def build_whitesub_text(entries, sub_id, sub):
    """entries: список (container_name, cfg). Формат совпадает с sub.md из olcRTC -
    plain text с #-глобальными полями и ##-локальными полями под каждым olcrtc://."""
    names_map = get_client_names()
    lines = [f"#name: {sub['name']}", f"#id: {sub_id}", f"#update: {int(time.time())}"]
    for container_name, cfg in entries:
        alias = names_map.get(container_name)
        label = alias if alias else container_name
        lines.append("")
        lines.append(cfg["uri"])
        lines.append(f"##name: {label}")
    return "\n".join(lines)


def handle_whitesub_deploy(message, count):
    pool = get_whitesub_pool()
    if not pool:
        bot.reply_to(
            message,
            "❌ Пул пуст. Сначала запусти `/whitesub -setup [N]` и подтверди рабочие позиции.",
            parse_mode="Markdown"
        )
        return

    hosts = [entry["host"] for entry in pool[:count]]
    note = f" (в пуле только {len(pool)}, поднимаю все)" if count > len(pool) else ""

    status = bot.reply_to(message, f"⏳ Поднимаю {len(hosts)} туннелей из пула{note}...")

    entries = []
    failed = []
    for host in hosts:
        try:
            container_name, room_id, uri = create_white_tunnel(host, source="whitesub")
            entries.append((container_name, {"uri": uri}))
        except Exception as e:
            failed.append((host, str(e)))

    sub_id, sub = get_active_whitesub_subscription()
    names_map = get_client_names()

    summary = [f"✅ *{sub['name']}* (`{sub_id}`) — поднято {len(entries)}/{len(hosts)}"]
    for container_name, cfg in entries:
        alias = names_map.get(container_name)
        label = alias if alias else container_name
        summary.append(f"`{label}`\n`{cfg['uri']}`")
    if failed:
        summary.append("❌ Ошибки:")
        for host, err in failed:
            summary.append(f"  `{host}`: {err}")
    summary.append(
        "\nОтветь на это сообщение текстом, чтобы задать имя подписки "
        "(сейчас видно в файле/ссылке как `#name:`)."
    )
    bot.delete_message(message.chat.id, status.message_id)
    sent = None
    chunk = ""
    for block in summary:
        candidate = f"{chunk}\n\n{block}" if chunk else block
        if len(candidate) > TELEGRAM_MSG_LIMIT:
            if chunk:
                sent = bot.send_message(message.chat.id, chunk, parse_mode="Markdown")
            chunk = block
        else:
            chunk = candidate
    if chunk:
        sent = bot.send_message(message.chat.id, chunk, parse_mode="Markdown")
    if sent:
        pending_whitesub_rename[sent.message_id] = sub_id

    if entries:
        text = build_whitesub_text(entries, sub_id, sub)
        save_whitesub_subscription_text(sub_id, text)

        file_buf = BytesIO(text.encode("utf-8"))
        file_buf.name = "whitesub.txt"
        bot.send_document(
            message.chat.id,
            file_buf,
            caption=(
                f"📦 Подписка «{sub['name']}» (`{sub_id}`), {len(entries)} профилей\n"
                "Импортируй файл в olcbox: добавление конфигурации → импорт из файла."
            )
        )

        link = whitesub_link_for(sub_id, sub)
        if link:
            bot.send_message(
                message.chat.id,
                "🔗 Или ссылкой (обновляется этим же адресом при каждом `/whitesub`):\n"
                f"`{link}`\n"
                "В olcbox: добавление конфигурации → ввести ссылку → включи "
                "`Allow insecure requests` (сертификат самоподписанный, это ожидаемо).",
                parse_mode="Markdown"
            )


def handle_whitesub_setup(message, count, check_anonymous_login=True):
    msg = bot.reply_to(
        message,
        f"🧮 Получаю список Jitsi-серверов (оба теста, займёт пару минут)... Цель: {count} рабочих подключений."
    )
    last_edit = {"t": 0.0}

    try:
        hosts = fetch_jitsi_candidates(check_anonymous_login=check_anonymous_login)
    except Exception as e:
        bot.edit_message_text(f"❌ Не удалось получить список серверов: {e}", message.chat.id, msg.message_id)
        return

    def make_progress_cb(stage_label):
        def progress_cb(done, total, found):
            now = time.monotonic()
            if done != total and now - last_edit["t"] < JITSI_SCAN_PROGRESS_MIN_INTERVAL:
                return
            last_edit["t"] = now
            try:
                bot.edit_message_text(
                    f"🧮 {stage_label}: {done}/{total} (осталось {total - done}), рабочих найдено: {found}",
                    message.chat.id, msg.message_id
                )
            except Exception:
                pass
        return progress_cb

    try:
        latency_results, total = scan_best_jitsi(make_progress_cb("Этап 1/2, задержка"), hosts=hosts)
        speed_results, _ = scan_best_long_jitsi(make_progress_cb("Этап 2/2, скорость"), hosts=hosts)
    except Exception as e:
        bot.edit_message_text(f"❌ Ошибка во время сканирования: {e}", message.chat.id, msg.message_id)
        return

    if not latency_results and not speed_results:
        bot.edit_message_text(
            f"❌ Просканировано {total} серверов, ни один не ответил ни в одном из тестов.",
            message.chat.id, msg.message_id
        )
        return

    combined = compute_combined_scores(hosts, latency_results, speed_results)

    bot.edit_message_text(
        f"✅ Просканировано {total}. Полный список - следующим сообщением.\n"
        "Открой несколько вручную (браузером/телефоном в своей сети) и ответь "
        "на сообщение-приглашение ниже номерами позиций, которые реально работают "
        f"(например: 1, 3, 7, 12). Возьму лучшие {count} из подтверждённых.",
        message.chat.id, msg.message_id, parse_mode="Markdown"
    )

    send_long_message(
        message.chat.id,
        "📋 *Полный список (комбинированный балл):*\n" + format_combined_results_list(combined),
        parse_mode="Markdown"
    )

    prompt = bot.send_message(
        message.chat.id,
        f"👉 Ответь НА ЭТО сообщение номерами позиций из списка выше, которые ты проверил "
        f"и они реально работают (через запятую или пробел). Возьму лучшие {count} из них."
    )
    pending_whitesub_setup[prompt.message_id] = {
        "combined": combined,
        "count": count,
        "checked": check_anonymous_login,
    }


def process_whitesub_setup_reply(message, reply_id):
    data = pending_whitesub_setup.pop(reply_id)
    combined = data["combined"]
    count = data["count"]
    checked = data.get("checked", True)
    total = len(combined)

    positions = []
    for tok in re.findall(r'\d+', message.text):
        n = int(tok)
        if n not in positions:
            positions.append(n)

    valid_positions = sorted(p for p in positions if 1 <= p <= total)
    invalid_positions = [p for p in positions if p not in valid_positions]

    if not valid_positions:
        bot.reply_to(
            message,
            "⛔ Не нашёл ни одной валидной позиции в ответе. Пришли номера из списка (например: 1, 3, 7)."
        )
        return

    chosen_positions = valid_positions[:count]
    skipped_over_limit = valid_positions[count:]
    checks_label = "ok" if checked else "skipped"
    hosts = [
        {"host": combined[p - 1][0], "checks": checks_label}
        for p in chosen_positions
    ]

    save_whitesub_pool(hosts)

    summary_lines = [
        f"✅ Пул из {len(hosts)} доменов сохранён (позиции: {', '.join(f'#{p}' for p in chosen_positions)}).",
        "Используй `/whitesub [N]`, чтобы поднять N туннелей из пула и сразу получить файл подписки.",
    ]
    if invalid_positions:
        summary_lines.append(f"⚠️ Проигнорированы неверные позиции: {', '.join(map(str, invalid_positions))}")
    if skipped_over_limit:
        summary_lines.append(f"ℹ️ Позиции сверх лимита {count}: {', '.join(map(str, skipped_over_limit))}")

    bot.reply_to(message, "\n".join(summary_lines), parse_mode="Markdown")


def parse_status():
    result = subprocess.run(
        ["docker", "exec", VPN_CONTAINER_NAME, "cat", STATUS_LOG],
        capture_output=True, text=True
    )
    clients = []
    in_clients = False
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Common Name"):
            in_clients = True
            continue
        if line.startswith("ROUTING TABLE"):
            in_clients = False
            continue
        if in_clients and line:
            parts = line.split(",")
            if len(parts) >= 4:
                clients.append({
                    "name": parts[0],
                    "addr": parts[1],
                    "bytes_recv": int(parts[2]),
                    "bytes_sent": int(parts[3]),
                    "since": parts[4]
                })
    return clients


def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            return json.load(f)
    return []


def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f)


def format_bytes(b):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def format_bits_per_sec(bps):
    for unit in ["bps", "Kbps", "Mbps", "Gbps"]:
        if bps < 1000:
            return f"{bps:.1f} {unit}"
        bps /= 1000
    return f"{bps:.1f} Tbps"


def list_openvpn_clients():
    """Все клиентские сертификаты, когда-либо выданные ботом (/new).
    Сервер сам себе тоже выдаёт сертификат (CN=IP) - он не начинается с "user_",
    поэтому исключается явно, а не через сверку с текущим OVPN_CN (после смены
    сервера/IP это сравнение внутри ovpn_listclients больше не совпадает)."""
    result = subprocess.run(
        ["docker", "exec", VPN_CONTAINER_NAME, "ovpn_listclients"],
        capture_output=True, text=True, check=True
    )
    clients = []
    lines = result.stdout.strip().splitlines()
    for line in lines[1:]:  # первая строка - заголовок CSV
        parts = line.split(",")
        if len(parts) < 4:
            continue
        name, status = parts[0], parts[3]
        if not name.startswith("user_"):
            continue
        clients.append({"name": name, "status": status})
    return clients


def format_openvpn_list():
    try:
        certs = list_openvpn_clients()
    except Exception as e:
        return f"❌ Не удалось получить список OpenVPN-клиентов: {e}"

    try:
        connected = {c["name"]: c for c in parse_status()}
    except Exception:
        connected = {}

    rows = []
    for cert in certs:
        name = cert["name"]
        conn = connected.get(name)
        if conn:
            total = conn["bytes_recv"] + conn["bytes_sent"]
            rows.append((name, True, total, conn["bytes_recv"], conn["bytes_sent"], cert["status"]))
        else:
            rows.append((name, False, 0, 0, 0, cert["status"]))

    rows.sort(key=lambda r: r[2], reverse=True)

    if not rows:
        return "🔒 *OpenVPN* (0): клиентов нет."

    names_map = get_client_names()
    lines = [f"🔒 *OpenVPN* ({len(rows)}):"]
    for i, (name, online, total, recv, sent, status) in enumerate(rows, start=1):
        marker = "🟢" if online else "⚪"
        status_note = "" if status == "VALID" else f" [{status}]"
        alias = names_map.get(name)
        label = f"{alias} (`{name}`)" if alias else f"`{name}`"
        if online:
            lines.append(f"{i}. {marker} {label}{status_note} — {format_bytes(total)} (↓{format_bytes(recv)} / ↑{format_bytes(sent)})")
        else:
            lines.append(f"{i}. {marker} {label}{status_note} — офлайн")
    return "\n".join(lines)


def format_uptime(seconds):
    if seconds is None:
        return "?"
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}ч {m}м"
    if m:
        return f"{m}м"
    return f"{s}с"


def list_white_containers():
    """Живые white-туннели (olcrtc-контейнеры). Работают с --network host,
    поэтому у Docker нет отдельного сетевого трафика на контейнер - вместо этого
    показываем CPU% (как индикатор активности) и аптайм."""
    result = subprocess.run(
        ["docker", "ps", "--filter", f"ancestor={OLCRTC_IMAGE}", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=True
    )
    names = [n for n in result.stdout.strip().splitlines() if n]
    if not names:
        return []

    stats_result = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.Name}},{{.CPUPerc}}"] + names,
        capture_output=True, text=True, check=True
    )
    cpu_by_name = {}
    for line in stats_result.stdout.strip().splitlines():
        parts = line.split(",")
        if len(parts) == 2:
            cpu_by_name[parts[0]] = parts[1].strip().rstrip('%')

    rows = []
    for name in names:
        started_at = ""
        try:
            inspect_result = subprocess.run(
                ["docker", "inspect", name, "--format", "{{.State.StartedAt}}"],
                capture_output=True, text=True, check=True
            )
            started_at = inspect_result.stdout.strip()
        except Exception:
            pass

        uptime_sec = None
        try:
            started_dt = datetime.strptime(started_at[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            uptime_sec = (datetime.now(timezone.utc) - started_dt).total_seconds()
        except Exception:
            pass

        try:
            cpu_val = float(cpu_by_name.get(name, "0"))
        except ValueError:
            cpu_val = 0.0

        rows.append({"name": name, "cpu": cpu_val, "uptime_sec": uptime_sec})

    rows.sort(key=lambda r: r["cpu"], reverse=True)
    return rows


def format_white_list():
    try:
        rows = list_white_containers()
    except Exception as e:
        return f"❌ Не удалось получить список White-туннелей: {e}"

    if not rows:
        return "🌐 *White/Jitsi* (0): туннелей нет."

    names_map = get_client_names()
    lines = [f"🌐 *White/Jitsi* ({len(rows)}):"]
    for i, r in enumerate(rows, start=1):
        alias = names_map.get(r['name'])
        label = f"{alias} (`{r['name']}`)" if alias else f"`{r['name']}`"
        lines.append(f"{i}. {label} — CPU {r['cpu']:.1f}%, аптайм {format_uptime(r['uptime_sec'])}")
    return "\n".join(lines)


@bot.message_handler(commands=['list'])
def handle_list(message):
    if not is_admin(message):
        bot.reply_to(message, "⛔ Команда доступна только администратору.")
        return

    msg = bot.reply_to(message, "⏳ Собираю список клиентов...")

    text = format_openvpn_list() + "\n\n" + format_white_list()

    try:
        bot.delete_message(message.chat.id, msg.message_id)
    except Exception:
        pass
    send_long_message(message.chat.id, text, parse_mode="Markdown")


@bot.message_handler(commands=['monitor'])
def handle_monitor(message):
    msg = bot.reply_to(message, "⏳ Собираю данные мониторинга...")

    try:
        clients = parse_status()
        now = time.time()
        total_recv = sum(c["bytes_recv"] for c in clients)
        total_sent = sum(c["bytes_sent"] for c in clients)

        history = load_history()
        history.append({
            "time": now,
            "total_bytes": total_recv + total_sent
        })
        one_hour_ago = now - 3600
        history = [h for h in history if h["time"] >= one_hour_ago]
        save_history(history)

        bw_text = "Нет данных за последний час (нужно два замера)"
        pct_text = ""
        if len(history) >= 2:
            first = history[0]
            last = history[-1]
            elapsed = last["time"] - first["time"]
            if elapsed > 0:
                bits = (last["total_bytes"] - first["total_bytes"]) * 8
                bps = bits / elapsed
                bw_text = format_bits_per_sec(bps)
                pct = (bps / BW_LIMIT) * 100
                pct_text = f" ({pct:.1f}% от 1 Гбит/с)"

        lines = [f"📊 *Мониторинг VPN*\n"]
        lines.append(f"👥 *Клиенты:* {len(clients)}")
        if clients:
            lines.append("")
            for c in clients:
                total = format_bytes(c["bytes_recv"] + c["bytes_sent"])
                lines.append(f"  └ `{c['name']}` — {total}")
        lines.append("")
        lines.append(f"📥 Принято: {format_bytes(total_recv)}")
        lines.append(f"📤 Отправлено: {format_bytes(total_sent)}")
        lines.append(f"📈 Средняя нагрузка за час: {bw_text}{pct_text}")

        bot.edit_message_text("\n".join(lines), message.chat.id, msg.message_id, parse_mode="Markdown")

    except Exception as e:
        bot.edit_message_text(f"❌ Ошибка: {str(e)}", message.chat.id, msg.message_id)


def take_snapshot():
    try:
        clients = parse_status()
        now = time.time()
        total = sum(c["bytes_recv"] + c["bytes_sent"] for c in clients)
        history = load_history()
        history.append({"time": now, "total_bytes": total})
        cutoff = now - 3600
        history = [h for h in history if h["time"] >= cutoff]
        save_history(history)
    except Exception:
        pass


def snapshot_loop():
    while True:
        take_snapshot()
        time.sleep(300)


def resolve_client_key(text):
    """Ищет конфиг по реальному имени (user_xxx / olcrtc-xxx) или по алиасу, заданному через reply."""
    names_map = get_client_names()
    for real_name, alias in names_map.items():
        if alias == text:
            return real_name

    if text.startswith("user_"):
        try:
            certs = list_openvpn_clients()
        except Exception:
            certs = []
        if any(c["name"] == text for c in certs):
            return text

    if text.startswith("olcrtc-"):
        if text in get_white_configs():
            return text
        try:
            running = {r["name"] for r in list_white_containers()}
        except Exception:
            running = set()
        if text in running:
            return text

    return None


def send_config_info(chat_id, key):
    names_map = get_client_names()
    alias = names_map.get(key)
    label = f"{alias} ({key})" if alias else key

    if key.startswith("user_"):
        try:
            result = subprocess.run(
                ["docker", "exec", VPN_CONTAINER_NAME, "ovpn_getclient", key],
                capture_output=True, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            bot.send_message(chat_id, f"❌ Не удалось получить конфиг: {e.stderr}")
            return

        file_path = f"{key}.ovpn"
        with open(file_path, "w") as f:
            f.write(result.stdout)
        try:
            with open(file_path, "rb") as f:
                sent = bot.send_document(
                    chat_id, f,
                    caption=(
                        f"📄 OpenVPN: {label}\n\n"
                        "Ответь на это сообщение текстом, чтобы задать имя, видимое в /list."
                    ),
                )
        finally:
            os.remove(file_path)

        pending_rename[sent.message_id] = key
        return

    if key.startswith("olcrtc-"):
        cfg = get_white_configs().get(key)
        if not cfg:
            bot.send_message(
                chat_id,
                f"❌ Нет сохранённых данных для `{key}` (создан до обновления бота, конфиг утерян).",
                parse_mode="Markdown"
            )
            return

        uri = cfg["uri"]
        qr_buf = BytesIO()
        qrcode.make(uri).save(qr_buf, format="PNG")
        qr_buf.seek(0)

        sent = bot.send_photo(
            chat_id, qr_buf,
            caption=(
                f"🌐 White: {label}\n"
                f"Jitsi: `{cfg['jitsi_instance']}`\n"
                f"Комната: `{cfg['room_id']}`\n\n"
                f"`{uri}`\n\n"
                "Ответь на это сообщение текстом, чтобы задать имя, видимое в /list."
            ),
            parse_mode="Markdown"
        )
        pending_rename[sent.message_id] = key
        return


@bot.message_handler(func=lambda m: bool(m.text) and not m.text.startswith('/'))
def handle_text(message):
    if not is_admin(message):
        return  # молча игнорируем, не спамим не-админам в личке с ботом

    try:
        text = message.text.strip()

        if message.reply_to_message:
            reply_id = message.reply_to_message.message_id

            if reply_id in pending_whitesub_setup:
                process_whitesub_setup_reply(message, reply_id)
                return

            if reply_id in pending_whitesub_rename:
                sub_id = pending_whitesub_rename.pop(reply_id)
                name = sanitize_alias(text)
                if rename_whitesub_subscription(sub_id, name):
                    bot.reply_to(message, f"✅ Имя подписки `{sub_id}` обновлено: {name}", parse_mode="Markdown")
                else:
                    bot.reply_to(message, f"⛔ Подписка `{sub_id}` больше не существует.", parse_mode="Markdown")
                return

            if reply_id in pending_whitesub_config:
                handle_whitesub_config_reply(message)
                return

            if reply_id in pending_rename:
                key = pending_rename.pop(reply_id)
                alias = sanitize_alias(text)
                set_client_name(key, alias)
                bot.reply_to(message, f"✅ Имя для `{key}` обновлено: {alias}", parse_mode="Markdown")
                return

        key = resolve_client_key(text)
        if key is None:
            return  # не похоже на имя конфига - молчим, не мусорим в чат

        send_config_info(message.chat.id, key)
    except Exception as e:
        # не даём необработанному исключению уронить весь polling-луп бота
        try:
            bot.reply_to(message, f"❌ Ошибка: {e}")
        except Exception:
            pass


if __name__ == "__main__":
    take_snapshot()
    t = threading.Thread(target=snapshot_loop, daemon=True)
    t.start()

    sub_server_thread = threading.Thread(target=start_subscription_server, daemon=True)
    sub_server_thread.start()

    print("Бот запущен...")
    bot.infinity_polling()
