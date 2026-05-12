import os
import asyncio
import re
import asyncpg
from dotenv import load_dotenv
from datetime import datetime
from pyrogram import Client, filters

load_dotenv()

# Секреты
API_ID = int(os.getenv("API_ID", 0))
API_HASH = os.getenv("API_HASH")
ALERT_CHAT_ID = int(os.getenv("ALERT_CHAT_ID", 0))
DATABASE_URL = os.getenv("DATABASE_URL")

# ЧАТЫ
listen_raw = os.getenv("LISTEN_CHATS", "")
LISTEN_CHATS = [int(i.strip()) for i in listen_raw.split(",") if i.strip()]
TARGET_CHATS = [ALERT_CHAT_ID]

# СПИСКИ
ALLOWED_IPS = os.getenv("ALLOWED_IPS", "").split(",")
ALLOWED_USERS = os.getenv("ALLOWED_USERS", "").split(",")
IGNORE_BAD_IP_CLIENTS = os.getenv("IGNORE_BAD_IP_CLIENTS", "").split(",")
CPANEL_SKIP_IPS = os.getenv("CPANEL_SKIP_IPS", "").split(",")
ATAK_SKIP_IPS = os.getenv("ATAK_SKIP_IPS", "").split(",")

WATCH_LIST = {
    ("itc", "Kronex_evrosklad-new"): "контроль доступа itc на Kronex_evrosklad-new",
    ("zruchna", "VetMedia-PBX-Sys"): "контроль доступа ZRUCHNA на VetMedia-PBX-Sys",
    ("itcenter", "Nemokna-new-ats"): "контроль доступа itcenter на Nemokna-new-ats",
    ("itcenter", "Confidens"): "контроль доступа itcenter на Confidens",
    ("itcenter_sergeym", "Sonodin-new"): "контроль доступа itcenter_sergeym на Sonodin-new",
    ("zruchna", "PBX-Ulc-LXC"): "контроль доступа zruchna на PBX-Ulc-LXC",
    ("itcenter", "pbx-bydom-lxc"): "контроль доступа itcenter на pbx-bydom-lxc",
    ("zruchna", "PBX-DPM_New-VM-mtscloud"): "контроль доступа zruchna на PBX-DPM_New-VM-mtscloud"
}

db_pool = None
failed_attempts = {} 
pending_checks = {}  
pending_attacks = {}

app = Client("my_account", api_id=API_ID, api_hash=API_HASH)

async def init_db():
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL)
    async with db_pool.acquire() as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY, reason TEXT, message_text TEXT, client_ip TEXT, timestamp TIMESTAMP DEFAULT NOW()
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY, client_ip TEXT UNIQUE, reason TEXT, timestamp TIMESTAMP DEFAULT NOW()
            )
        ''')

async def save_alert(reason, message_text, client_ip):
    async with db_pool.acquire() as conn:
        await conn.execute("INSERT INTO alerts (reason, message_text, client_ip) VALUES ($1, $2, $3)", reason, message_text, client_ip)

async def register_incident(client_ip, reason):
    async with db_pool.acquire() as conn:
        await conn.execute("INSERT INTO incidents (client_ip, reason) VALUES ($1, $2) ON CONFLICT DO NOTHING", client_ip, reason)

def parse_ssh_message(text):
    is_success = "SSH-авторизация" in text
    user_match = re.search(r"👤 Пользователь:\s*(.+)", text)
    ip_match = re.search(r"🌍 Клиент:\s*(.+)", text)
    method_match = re.search(r"🔑 Метод:\s*(.+)", text)
    zabbix_match = re.search(r"📊 Zabbix:\s*(.+)", text)
    return {
        "is_success": is_success,
        "user": user_match.group(1).strip() if user_match else None,
        "ip": ip_match.group(1).strip() if ip_match else None,
        "method_is_key": "ключ" in method_match.group(1).lower() if method_match else False,
        "zabbix_name": zabbix_match.group(1).strip() if zabbix_match else None
    }

def is_working_hours():
    now = datetime.now()
    if 7 <= now.hour < 21:
        if now.hour == 7 and now.minute < 30: return False
        return True
    return False

# Таймер для обычного SSH
async def wait_for_success(client_ip, original_message):
    await asyncio.sleep(60)
    reason = "[Инцидент]: нет успешной авторизации за 60 секунд после ошибки"
    
    await save_alert(reason, original_message.text, client_ip)
    await register_incident(client_ip, reason)
    
    for chat in TARGET_CHATS:
        try: 
            await client.send_message(chat, f"***{reason}***")
            await original_message.copy(chat)
        except Exception as e: print(f"[!] Ошибка копирования в {chat}: {e}", flush=True)
    print(f"[ALLERT] {reason} | IP: {client_ip}", flush=True)

# Таймер для WATCH_LIST
async def wait_for_watchlist_success(client, client_ip, original_message, control_text):
    await asyncio.sleep(60)
    reason = f"КОНТРОЛЬ ДОСТУПА: {control_text} [НЕТ УСПЕШНОГО ВХОДА ЗА 60 СЕК]"
    await save_alert(reason, original_message.text, client_ip)
    await register_incident(client_ip, reason)
    for chat in TARGET_CHATS:
        try:
            await client.send_message(chat, f"***{reason}***")
            await original_message.copy(chat)
        except Exception as e: print(f"[!] Ошибка в {chat}: {e}", flush=True)
    print(f"[ALLERT] {reason} | IP: {client_ip}", flush=True)

# Таймер для АТАК
async def wait_for_atak_resolution(client, src_ip, original_message):
    await asyncio.sleep(60)
    reason = f"[Инцидент]: Зафиксирована активность с IP: {src_ip} (нет подтверждения DST за 60 сек)"
    await save_alert(reason, original_message.text, src_ip)
    await register_incident(src_ip, reason)
    for chat in TARGET_CHATS:
        try: 
            await client.send_message(chat, f"***{reason}***")
            await original_message.copy(chat)
        except Exception as e: print(f"[!] Ошибка алерта атаки в {chat}: {e}", flush=True)
    print(f"[ALLERT] {reason} | IP: {src_ip}", flush=True)

@app.on_message(filters.command(["status", "ping"]))
async def check_bot_status(client, message):
    if message.chat.id in TARGET_CHATS or message.chat.id in LISTEN_CHATS:
        uptime_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        await message.reply_text(
            f"**[ СТАТУС: БОТ АКТИВЕН ]**\n"
            f"Время на сервере: {uptime_time}\n"
            f"Слушаю чатов: {len(LISTEN_CHATS)}\n"
            f"Шлю алерты в чатов: {len(TARGET_CHATS)}\n"
            f"Мониторинг логов активен"
        )
@app.on_message(filters.chat(LISTEN_CHATS)) 
async def analyze_ssh_log(client, message):
    if not (message.from_user and message.from_user.is_bot): return 
    text = message.text or message.caption or ""
    if not text: return

    if "WEB_SRC_Atak_" in text:
        found_ip = re.search(r"WEB_SRC_Atak_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if found_ip:
            src_ip = found_ip.group(1)
            
            # ПРОВЕРКА НА ИСКЛЮЧЕНИЕ АТАКИ
            if src_ip in ATAK_SKIP_IPS:
                print(f"[log] Игнор WEB_SRC_Atak от {src_ip} (в списке исключений ATAK_SKIP_IPS)", flush=True)
                return

            zabbix_node = text.strip().split('\n')[0].strip()
            
            print(f"[*] Запуск таймера 60с для атаки SRC IP: {src_ip} (узел {zabbix_node})", flush=True)
            task = asyncio.create_task(wait_for_atak_resolution(client, src_ip, message))
            pending_attacks[zabbix_node] = task
        return 

    if "WEB_DST_Atak_" in text:
        found_ip = re.search(r"WEB_DST_Atak_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if found_ip:
            dst_ip = found_ip.group(1)
            
            # ПРОВЕРКА НА ИСКЛЮЧЕНИЕ АТАКИ
            if dst_ip in ATAK_SKIP_IPS:
                print(f"[log] Игнор WEB_DST_Atak на {dst_ip} (в списке исключений ATAK_SKIP_IPS)", flush=True)
                return

            zabbix_node = text.strip().split('\n')[0].strip() 
            
            if zabbix_node in pending_attacks:
                print(f"[log] Получен DST IP: {dst_ip} (узел {zabbix_node}). Связка успешна, алерт отменен.", flush=True)
                pending_attacks[zabbix_node].cancel()
                del pending_attacks[zabbix_node]
            else:
                print(f"[log] Получен DST IP: {dst_ip}, но таймер SRC для {zabbix_node} не запускался.", flush=True)
        return 

    # ПЕРЕХВАТЧИК CPANEL 
    SKIP_KEYWORDS = ["Cpanel_SSH_Actiivty"]
    if any(key in text for key in SKIP_KEYWORDS):
        found_ip = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if found_ip:
            ip_val = found_ip.group(1)
            if ip_val in CPANEL_SKIP_IPS:
                print(f"[log] игнор {ip_val} по системному ключу Cpanel", flush=True)
                return
            else:
                alert_reason = f"Подозрительная активность Cpanel с НЕИЗВЕСТНОГО IP: {ip_val}"
                print(f"[!] АХТУНГ: {alert_reason}", flush=True)
                await save_alert(alert_reason, text, ip_val)
                for chat in TARGET_CHATS:
                    try:
                        await client.send_message(chat, f"***{alert_reason}***")
                        await message.copy(chat)
                    except Exception as e: print(f"[!] Ошибка отправки: {e}", flush=True)
                return

    # СТАНДАРТНЫЙ ПАРСИНГ SSH 
    parsed = parse_ssh_message(text)
    user, ip, zabbix_name = parsed["user"], parsed["ip"], parsed["zabbix_name"]
    
    if not user or not ip:
        print(f"[log] Формат не SSH:\n{text}\n", flush=True)
        return 
    
    print(f"\n[log] юзер: {user} | Zabbix: {zabbix_name} | IP: {ip}", flush=True)
    
    alert_reason = None
    pair = (user, zabbix_name)

    # ЛОГИКА УСПЕШНОЙ АВТОРИЗАЦИИ
    if parsed["is_success"]:
        if ip in pending_checks:
            pending_checks[ip].cancel()
            del pending_checks[ip]
        if ip in failed_attempts: failed_attempts[ip] = 0

        if pair in WATCH_LIST:
            print(f"[whatch_list]: {WATCH_LIST[pair]} [УСПЕХ]", flush=True)
            return
        
        if not alert_reason:
            if not is_working_hours(): alert_reason = "успешный вход в нерабочее время"
            elif user == "root" and not parsed["method_is_key"]: alert_reason = "root авторизовался НЕ по ключу"
            elif user != "root" and user not in ALLOWED_USERS: alert_reason = f"пользователь {user} не в списке разрешенных"

    # ЛОГИКА НЕУДАЧНОЙ АВТОРИЗАЦИИ
    else:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        if pair in WATCH_LIST:
            print(f"[whatch_list]: {WATCH_LIST[pair]} [НЕУДАЧА]", flush=True)
            if ip not in pending_checks:
                print(f"[*] Запуск таймера 60с для WATCH_LIST ({ip})", flush=True)
                task = asyncio.create_task(wait_for_watchlist_success(client, ip, message, WATCH_LIST[pair]))
                pending_checks[ip] = task
            return
            
        elif not alert_reason:
            if failed_attempts[ip] > 2:
                alert_reason = f"Обнаружено более 2-х неудачных попыток ({failed_attempts[ip]})"
                await register_incident(ip, alert_reason)

        # таймер True Positive для остальных
        if user not in IGNORE_BAD_IP_CLIENTS:
            if ip not in ALLOWED_IPS and not parsed["method_is_key"]:
                if ip not in pending_checks:
                    print(f"[*] Запуск таймера 60 сек для {ip}", flush=True)
                    task = asyncio.create_task(wait_for_success(client, ip, message))
                    pending_checks[ip] = task

    # ОТПРАВКА АЛЕРТА
    if alert_reason:
        print(f"[!] АХТУНГ: {alert_reason}", flush=True)
        await save_alert(alert_reason, text, ip)
        for chat in TARGET_CHATS:
            try:
                await client.send_message(chat, f"***{alert_reason}***")
                await message.copy(chat)
            except Exception as e: print(f"[!] Ошибка в {chat}: {e}", flush=True)

async def start_bot():
    print("Подключение к базе данных PostgreSQL", flush=True)
    await init_db()
    
    await app.start()
    print("Бот запущен. Скан начат.", flush=True)
    
    # сообщениео успешном старте или перезапуске
    startup_msg = "IDS Бот успешно запущен/перезагружен"
    for chat in TARGET_CHATS:
        try:
            await app.send_message(chat, startup_msg)
        except Exception as e:
            print(f"[!] Не удалось отправить сообщение о старте в {chat}: {e}")

    from pyrogram import idle
    await idle()
    
    # сообщение при выключении контейнера
    shutdown_msg = "IDS БОТ остановлен (выключен контейнер)"
    for chat in TARGET_CHATS:
        try:
            await app.send_message(chat, shutdown_msg)
        except Exception as e:
            pass

    await app.stop()

if __name__ == "__main__":
    try: 
        app.loop.run_until_complete(start_bot())
    except KeyboardInterrupt:
        print("Бот остановлен вручную.")
    except Exception as e: 
        print(f"Критическая ошибка: {e}")
