import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

import main

pytestmark = pytest.mark.asyncio

@pytest.fixture(autouse=True)
def setup_test_environment():
    main.failed_attempts.clear()
    main.pending_checks.clear()
    main.pending_attacks.clear()
    main.last_success_time.clear()
    main.ansible_test_active = False
    main.ansible_test_results.clear()
    
    main.LISTEN_CHATS = [1111]
    main.TARGET_CHATS = [2222]
    
    main.ALLOWED_IPS = ["192.168.1.50"]
    main.ALLOWED_USERS = ["zruchna", "misha"]
    main.IGNORE_BAD_IP_CLIENTS = []
    main.CPANEL_SKIP_IPS = ["10.0.0.5"]
    main.ATAK_SKIP_IPS = ["10.0.0.10"]
    
    main.save_alert = AsyncMock()
    main.register_incident = AsyncMock()

def create_mock_message(text):
    message = MagicMock()
    message.chat.id = 1111
    message.text = text
    message.caption = None
    message.from_user.is_bot = True
    message.copy = AsyncMock()
    return message

async def test_single_attack_trigger():
    client_mock = MagicMock()
    client_mock.send_message = AsyncMock()
    msg = create_mock_message("Node\nAtak_198.51.100.1")
    
    await main.analyze_ssh_log(client_mock, msg)
    
    client_mock.send_message.assert_called_once()
    main.register_incident.assert_called_once()

async def test_single_attack_skipped():
    client_mock = MagicMock()
    client_mock.send_message = AsyncMock()
    msg = create_mock_message("Node\nAtak_10.0.0.10")
    
    await main.analyze_ssh_log(client_mock, msg)
    
    client_mock.send_message.assert_not_called()

async def test_web_src_starts_timer():
    client_mock = MagicMock()
    msg = create_mock_message("Test-Node\nWEB_SRC_Atak_198.51.100.2")
    
    await main.analyze_ssh_log(client_mock, msg)
    
    assert "Test-Node" in main.pending_attacks
    main.pending_attacks["Test-Node"].cancel()

async def test_web_dst_cancels_timer():
    client_mock = MagicMock()
    mock_task = MagicMock()
    main.pending_attacks["Test-Node"] = mock_task
    msg = create_mock_message("Test-Node\nWEB_DST_Atak_198.51.100.2")
    
    await main.analyze_ssh_log(client_mock, msg)
    
    mock_task.cancel.assert_called_once()
    assert "Test-Node" not in main.pending_attacks

async def test_cpanel_activity_alert():
    client_mock = MagicMock()
    client_mock.send_message = AsyncMock()
    msg = create_mock_message("Cpanel_SSH_Actiivty from 198.51.100.3")
    
    await main.analyze_ssh_log(client_mock, msg)
    
    client_mock.send_message.assert_called_once()

async def test_cpanel_activity_skipped():
    client_mock = MagicMock()
    client_mock.send_message = AsyncMock()
    msg = create_mock_message("Cpanel_SSH_Actiivty from 10.0.0.5")
    
    await main.analyze_ssh_log(client_mock, msg)
    
    client_mock.send_message.assert_not_called()

async def test_ssh_success_resets_state():
    client_mock = MagicMock()
    main.failed_attempts["192.168.1.50"] = 5
    main.pending_checks["192.168.1.50"] = MagicMock()
    
    log = "🖥 SSH-авторизация\n👤 Пользователь: misha\n🔑 Метод: ключ\n🌍 Клиент: 192.168.1.50\n📊 Zabbix: Node"
    msg = create_mock_message(log)
    
    with patch("main.is_working_hours", return_value=True):
        await main.analyze_ssh_log(client_mock, msg)
        
    assert main.failed_attempts["192.168.1.50"] == 0
    assert "192.168.1.50" not in main.pending_checks
    assert "192.168.1.50" in main.last_success_time

async def test_ssh_success_off_hours_alert():
    client_mock = MagicMock()
    client_mock.send_message = AsyncMock()
    
    log = "🖥 SSH-авторизация\n👤 Пользователь: misha\n🔑 Метод: ключ\n🌍 Клиент: 192.168.1.50\n📊 Zabbix: Node"
    msg = create_mock_message(log)
    
    with patch("main.is_working_hours", return_value=False):
        await main.analyze_ssh_log(client_mock, msg)
        
    main.save_alert.assert_called_once_with("успешный вход в нерабочее время", log, "192.168.1.50")

async def test_ssh_success_root_no_key_alert():
    client_mock = MagicMock()
    
    log = "🖥 SSH-авторизация\n👤 Пользователь: root\n🔑 Метод: пароль\n🌍 Клиент: 192.168.1.50\n📊 Zabbix: Node"
    msg = create_mock_message(log)
    
    with patch("main.is_working_hours", return_value=True):
        await main.analyze_ssh_log(client_mock, msg)
        
    main.save_alert.assert_called_once_with("root авторизовался НЕ по ключу", log, "192.168.1.50")

async def test_ssh_success_not_allowed_user_alert():
    client_mock = MagicMock()
    
    log = "🖥 SSH-авторизация\n👤 Пользователь: unknown_user\n🔑 Метод: ключ\n🌍 Клиент: 192.168.1.50\n📊 Zabbix: Node"
    msg = create_mock_message(log)
    
    with patch("main.is_working_hours", return_value=True):
        await main.analyze_ssh_log(client_mock, msg)
        
    main.save_alert.assert_called_once_with("пользователь unknown_user не в списке разрешенных", log, "192.168.1.50")

async def test_ssh_failure_immunity_ignored():
    client_mock = MagicMock()
    main.last_success_time["192.168.1.99"] = datetime.now().timestamp()
    
    log = "🚨 Неудачная авторизация\n👤 Пользователь: misha\n🌍 Клиент: 192.168.1.99\n📊 Zabbix: Node"
    msg = create_mock_message(log)
    
    await main.analyze_ssh_log(client_mock, msg)
    
    assert "192.168.1.99" not in main.pending_checks
    assert main.failed_attempts.get("192.168.1.99", 0) == 0

async def test_ssh_failure_bruteforce_alert():
    client_mock = MagicMock()
    main.failed_attempts["192.168.1.99"] = 2
    
    log = "🚨 Неудачная авторизация\n👤 Пользователь: misha\n🌍 Клиент: 192.168.1.99\n📊 Zabbix: Node"
    msg = create_mock_message(log)
    
    await main.analyze_ssh_log(client_mock, msg)
    
    main.register_incident.assert_called_once_with("192.168.1.99", "Обнаружено более 2-х неудачных попыток (3)")

async def test_ssh_failure_single_starts_timer():
    client_mock = MagicMock()
    
    log = "🚨 Неудачная авторизация\n👤 Пользователь: misha\n🌍 Клиент: 192.168.1.99\n📊 Zabbix: Node"
    msg = create_mock_message(log)
    
    await main.analyze_ssh_log(client_mock, msg)
    
    assert "192.168.1.99" in main.pending_checks
    main.pending_checks["192.168.1.99"].cancel()

async def test_watchlist_failure_starts_timer():
    client_mock = MagicMock()
    
    log = "🚨 Неудачная авторизация\n👤 Пользователь: itc\n🌍 Клиент: 192.168.1.99\n📊 Zabbix: Kronex_evrosklad-new"
    msg = create_mock_message(log)
    
    await main.analyze_ssh_log(client_mock, msg)
    
    assert "192.168.1.99" in main.pending_checks
    main.pending_checks["192.168.1.99"].cancel()