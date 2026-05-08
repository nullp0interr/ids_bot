import os
import asyncio
import re
import asyncpg
from dotenv import load_dotenv
from datetime import datetime
from pyrogram import Client, filters

load_dotenv()

API_ID = int(os.getenv("API_ID", 0))
API_HASH = os.getenv("API_HASH")
CHAT_ID = int(os.getenv("CHAT_ID", 0))
ALERT_CHAT_ID = int(os.getenv("ALERT_CHAT_ID", 0))
DATABASE_URL = os.getenv("DATABASE_URL")

ALLOWED_IPS = os.getenv("ALLOWED_IPS", "").split(",")
ALLOWED_USERS = os.getenv("ALLOWED_USERS", "").split(",")
IGNORE_BAD_IP_CLIENTS = os.getenv("IGNORE_BAD_IP_CLIENTS", "").split(",")

WATCH_LIST = {
    ("itc", "Kronex_evrosklad-new"): "контроль доступа itc на Kronex_evrosklad-new",
    ("zruchna", "VetMedia-PBX-Sys"): "контроль доступа ZRUCHNA на VetMedia-PBX-Sys",
    ("itcenter", "Nemokna-new-ats"): "контроль доступа itcenter на Nemokna-new-ats",
    ("itcenter", "Confidens"): "контроль доступа itcenter на Confidens",
    ("itcenter_sergeym", "Sonodin-new"): "контроль доступа itcenter_sergeym на Sonodin-new"
}
db_pool = None

failed_attempts = {} 
pending_checks = {}  

app = Client("my_account", api_id=API_ID, api_hash=API_HASH)

async def init_db():
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL)
    async with db_pool.acquire() as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                reason TEXT,
                message_text TEXT,
                client_ip TEXT,
                timestamp TIMESTAMP DEFAULT NOW()
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                client_ip TEXT UNIQUE,
                reason TEXT,
                timestamp TIMESTAMP DEFAULT NOW()
            )
        ''')

async def save_alert(reason, message_text, client_ip):
    async with db_pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO alerts (reason, message_text, client_ip) VALUES ($1, $2, $3)",
            reason, message_text, client_ip
        )

async def register_incident(client_ip, reason):
    async with db_pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO incidents (client_ip, reason) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            client_ip, reason
        )

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
        if now.hour == 7 and now.minute < 30:
            return False
        return True
    return False

async def wait_for_success(client_ip, original_message):
    await asyncio.sleep(60)
    reason = "[Инцидент]: нет успешной авторизации за 60 секунд после ошибки"
    await save_alert(reason, original_message.text, client_ip)
    await register_incident(client_ip, reason)
    await original_message.copy(ALERT_CHAT_ID)
    print(f"[ALLERT] {reason} | IP: {client_ip}")

@app.on_message(filters.chat(CHAT_ID)) 
async def analyze_ssh_log(client, message):
    if not (message.from_user and message.from_user.is_bot):
        return 
    
    text = message.text or message.caption or ""
    if not text: return
    
    parsed = parse_ssh_message(text)
    user = parsed["user"]
    ip = parsed["ip"]
    zabbix_name = parsed["zabbix_name"]
    
    if not user or not ip:
        print(f"[log] Формат не SSH:\n{text}\n")
        return 
    
    print(f"\n[log] юзер: {user} | Zabbix: {zabbix_name} | IP: {ip}")
    
    alert_reason = None
    pair = (user, zabbix_name)

    # ЛОГИКА УСПЕШНОЙ АВТОРИЗАЦИИ
    if parsed["is_success"]:
        if ip in pending_checks:
            pending_checks[ip].cancel()
            del pending_checks[ip]
        if ip in failed_attempts:
            failed_attempts[ip] = 0

        if pair in WATCH_LIST:
            alert_reason = f"[whatch_list]: {WATCH_LIST[pair]} [УСПЕХ]"
        
        if not alert_reason:
            if not is_working_hours():
                alert_reason = "успешный вход в нерабочее время"
            elif user == "root" and not parsed["method_is_key"]:
                alert_reason = "root авторизовался НЕ по ключу"
            elif user != "root" and user not in ALLOWED_USERS:
                alert_reason = f"пользователь {user} не в списке разрешенных"

    # ЛОГИКА НЕУДАЧНОЙ АВТОРИЗАЦИИ
    else:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        if pair in WATCH_LIST:
            alert_reason = f"[whatch_list]: {WATCH_LIST[pair]} [НЕУДАЧА]"

        if not alert_reason:
            if failed_attempts[ip] > 2:
                alert_reason = f"Обнаружено более 2-х неудачных попыток ({failed_attempts[ip]})"
                await register_incident(ip, alert_reason)

        # таймер True Positive,если юзер не в игноре
        if user not in IGNORE_BAD_IP_CLIENTS:
            if ip not in ALLOWED_IPS and not parsed["method_is_key"]:
                if ip not in pending_checks:
                    print(f"[*] Запуск таймера 60с для {ip}")
                    task = asyncio.create_task(wait_for_success(ip, message))
                    pending_checks[ip] = task

    # ОТПРАВКА АЛЕРТА
    if alert_reason:
        print(f"[!] АХТУНГ: {alert_reason}")
        await save_alert(alert_reason, text, ip)
        # здесь отправляю текстовый заголовок и копию сообщения в нашу группу
        # чат с Валерой!!!
        await client.send_message(ALERT_CHAT_ID, f"***{alert_reason}***")
        await message.copy(ALERT_CHAT_ID)

if __name__ == "__main__":
    print("Подключение к базе данных PostgreSQL...")
    try:
        app.loop.run_until_complete(init_db())
    except Exception as e:
        print(f"Ошибка БД: {e}"); exit(1)

    print("Бот запущен. Скан начат.")

    while True:
        try:
            app.run()
        except Exception as e:
            print(f"Ошибка: {e}")
            if "already waiting" in str(e): continue
            asyncio.sleep(5)