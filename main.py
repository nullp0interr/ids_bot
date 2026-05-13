import os
import asyncio
import re
import asyncpg
from dotenv import load_dotenv
from datetime import datetime
from pyrogram import Client, filters
from excel_reporter import generate_ansible_report
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

ANSIBLE_TEST_LIST = {
    "100kotlov-NewSys": "172.17.85.124",
    "AGS-PBX-SYS": "172.17.85.180",
    "AstikonSnab-VM": "172.17.85.61",
    "AutoDrug-92": "172.17.85.2",
    "BamService-VM": "172.17.85.118",
    "beau-universe": "172.17.85.29",
    "BelAgroVetFarm-Sys": "172.17.85.108",
    "BelAuditAlliance": "172.17.85.96",
    "BelSemTorgPlus-SYS": "172.17.85.101",
    "Clinica-ZZ-VM": "172.17.85.100",
    "Dipper-SYS": "172.17.85.30",
    "Evrolombard-SYS": "172.17.85.119",
    "Fabrika-Mamka-MSK": "172.17.85.5",
    "FaraonTrade": "172.17.85.131",
    "Furniland-SYS": "172.17.85.51",
    "Germestrast-okko": "172.17.85.55",
    "Gira-SYS": "172.17.85.83",
    "Hypervisor-RichKargo-Proxmox": "172.17.85.179",
    "IkonMarket-SYS": "172.17.85.77",
    "Inho-BecloudVM": "172.17.85.112",
    "IpMakarchuk-FerstRFATS": "172.17.85.137",
    "Kryshnya": "172.17.85.82",
    "Ladgorna-SYS": "172.17.85.66",
    "Lkon-sys": "172.17.85.27",
    "LXD-Levada_Airon-VM": "172.17.85.216",
    "Mediluks-new": "172.17.85.35",
    "Mejarol-Sys": "172.17.85.64",
    "MindiBy-Vm": "172.17.85.88",
    "Mysql-Levada_Airon-VM": "172.17.85.218",
    "PBX-11labs-VM": "172.17.85.123",
    "PBX-Alisveta-SYS": "172.17.85.174",
    "PBX-Amiko-SYS": "172.17.85.129",
    "PBX-AnitaBy-SYS": "172.17.85.219",
    "PBX-Antarion-VM": "172.17.85.144",
    "PBX-AnutaDent-VM": "172.17.85.54",
    "PBX-Armis-VM": "172.17.85.193",
    "PBX-AsiaTradeRF-Cloud": "172.17.85.221",
    "PBX-Asystent_Service-SYS": "172.17.85.197",
    "PBX-AutoStrong-RB-VM": "172.17.85.214",
    "PBX-AutoStrong-RF-VM": "172.17.85.215",
    "PBX-BabyBoss-SYS": "172.17.85.147",
    "PBX-BelarusTorg-SYS": "172.17.85.38",
    "PBX-BelKuhni-SYS": "172.17.85.184",
    "PBX-Belmotors-SYS": "172.17.85.201",
    "PBX-Bemotors-FerstRF": "172.17.85.227",
    "PBX-Blk7-SYS": "172.17.85.124",
    "PBX-Cezar-KZ-Cloud": "172.17.85.75",
    "PBX-ComplexMedia-Cloud": "172.17.85.203",
    "PBX-D-Prodact-VM": "172.17.85.46",
    "PBX-DPM_New-VM-mtscloud": "172.17.85.110"
}

db_pool = None
failed_attempts = {} 
pending_checks = {}  
pending_attacks = {}
last_success_time = {} # время последнего успешного входа по IP

ansible_test_active = False
ansible_test_results = {}

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
    server_ip_match = re.search(r"🖥 Сервер:\s*(.+)", text)
    method_match = re.search(r"🔑 Метод:\s*(.+)", text)
    zabbix_match = re.search(r"📊 Zabbix:\s*(.+)", text)
    return {
        "is_success": is_success,
        "user": user_match.group(1).strip() if user_match else None,
        "ip": ip_match.group(1).strip() if ip_match else None,
        "server_ip": server_ip_match.group(1).strip() if server_ip_match else None,
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
async def wait_for_success(client, client_ip, original_message):
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

# ================= КОМАНДЫ =================

@app.on_message(filters.command(["status", "ping"]))
async def check_bot_status(client, message):
    if message.chat.id in TARGET_CHATS or message.chat.id in LISTEN_CHATS:
        uptime_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        await message.reply_text(
            f"[ СТАТУС: БОТ АКТИВЕН ]\n"
            f"Время на сервере: {uptime_time}\n"
            f"Слушаю чатов: {len(LISTEN_CHATS)}\n"
            f"Шлю алерты в чатов: {len(TARGET_CHATS)}\n"
            f"Мониторинг логов активен"
        )

@app.on_message(filters.command("test_start"))
async def start_ansible_test(client, message):
    global ansible_test_active, ansible_test_results
    if message.chat.id in TARGET_CHATS or message.chat.id in LISTEN_CHATS:
        ansible_test_active = True
        ansible_test_results = {k: "NO" for k in ANSIBLE_TEST_LIST.keys()}
        await message.reply_text(f"**тестирование запущено**\nжду сообщения от {len(ANSIBLE_TEST_LIST)} серверов\n(не забыть) /test_stop")

@app.on_message(filters.command("test_stop"))
async def stop_ansible_test(client, message):
    global ansible_test_active, ansible_test_results
    if message.chat.id in TARGET_CHATS or message.chat.id in LISTEN_CHATS:
        ansible_test_active = False
        
        # Формируем текст
        ok_count = list(ansible_test_results.values()).count("OK")
        fail_count = len(ansible_test_results) - ok_count
        
        report_text = (
            f"**Тестирование завершено**\n"
            f"Успешных тестов: {ok_count}\n"
            f"Не прошли тест: {fail_count}\n\n"
        )
        
        if fail_count > 0:
            report_text += "Сформирован отчет с тестами которые не прошли."
        else:
            report_text += "Тест успешно отработал (100% покрытие)"
            
        # механика генерации отчета
        report_filename = f"report_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.xlsx"
        generate_ansible_report(ansible_test_results, ANSIBLE_TEST_LIST, report_filename)
        
        # отправка сообщения в тг 
        await client.send_document(
            chat_id=message.chat.id,
            document=report_filename,
            caption=report_text
        )
        
        # удаление файла из сервера
        if os.path.exists(report_filename):
            os.remove(report_filename)

# ================= ПАРСЕР ЛОГОВ =================

@app.on_message(filters.chat(LISTEN_CHATS)) 
async def analyze_ssh_log(client, message):
    if not (message.from_user and message.from_user.is_bot): return 
    text = message.text or message.caption or ""
    if not text: return

    # Одиночные атаки
    if "Atak_" in text and "WEB_SRC_Atak_" not in text and "WEB_DST_Atak_" not in text:
        found_ip = re.search(r"Atak_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if found_ip:
            attack_ip = found_ip.group(1)
            
            if attack_ip in ATAK_SKIP_IPS:
                print(f"[log] Игнор одиночной Atak_ от {attack_ip} (в списке исключений ATAK_SKIP_IPS)", flush=True)
                return

            alert_reason = f"[Инцидент]: Зафиксирована SSH активность с IP: {attack_ip}"
            print(f"[!] АХТУНГ: {alert_reason}", flush=True)
            
            await save_alert(alert_reason, text, attack_ip)
            await register_incident(attack_ip, alert_reason)
            
            for chat in TARGET_CHATS:
                try:
                    await client.send_message(chat, f"***{alert_reason}***")
                    await message.copy(chat)
                except Exception as e: 
                    print(f"[!] Ошибка отправки: {e}", flush=True)
        return 
        
    if "WEB_SRC_Atak_" in text:
        found_ip = re.search(r"WEB_SRC_Atak_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if found_ip:
            src_ip = found_ip.group(1)
            
            if src_ip in ATAK_SKIP_IPS:
                print(f"[log] Игнор WEB_SRC_Atak от {src_ip} (в списке исключений)", flush=True)
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
            
            if dst_ip in ATAK_SKIP_IPS:
                print(f"[log] Игнор WEB_DST_Atak на {dst_ip} (в списке исключений)", flush=True)
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
        last_success_time[ip] = datetime.now().timestamp()
        
        # ================= БЛОК ТЕСТИРОВАНИЯ ANSIBLE (ЛОГИКА "ИЛИ") =================
        if ansible_test_active:
            s_ip = parsed.get("server_ip")
            matched_key = None
            
            if zabbix_name in ANSIBLE_TEST_LIST:
                matched_key = zabbix_name
            else:
                for k, v in ANSIBLE_TEST_LIST.items():
                    if v == s_ip:
                        matched_key = k
                        break
                        
            if matched_key:
                ansible_test_results[matched_key] = "OK"
                print(f"[TEST] Успех: {matched_key} (Лог Zabbix: {zabbix_name}, IP: {s_ip})", flush=True)
        # ============================================================================
        
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
        # ИММУНИТЕТ НА 5 МИНУТ если этот IP успешно заходил менее 5 минут назад (300 сек) игнорим опечатки
        if ip in last_success_time and (datetime.now().timestamp() - last_success_time[ip]) < 300:
            print(f"[log] Игнор ошибки для {ip}: пользователь уже сидит на сервере (успех менее 5 мин назад)", flush=True)
            return

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
    
    startup_msg = "IDS Бот успешно запущен/перезагружен"
    for chat in TARGET_CHATS:
        try:
            await app.send_message(chat, startup_msg)
        except Exception as e:
            print(f"[!] Не удалось отправить сообщение о старте в {chat}: {e}")

    from pyrogram import idle
    await idle()
    
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
