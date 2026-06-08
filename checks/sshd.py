"""
Модуль аудита SSH-сервера
(CIS Benchmarks + ФСТЭК)

Проверяемые параметры:
  - Наличие файла /etc/ssh/sshd_config
  - PermitRootLogin — запрет прямого входа root (CIS 5.1.20, ФСТЭК 2.1.2)
  - PermitEmptyPasswords — запрет пустых паролей (CIS 5.1.19)
  - MaxAuthTries — ограничение попыток аутентификации (CIS 5.1.16)
  - IgnoreRhosts — игнорирование .rhosts (CIS 5.1.11)
  - HostbasedAuthentication — хостовая аутентификация (CIS 5.1.10)
  - PermitUserEnvironment — пользовательские переменные окружения (CIS 5.1.21)
  - ClientAliveInterval — интервал проверки живых сессий (CIS 5.1.7)
  - ClientAliveCountMax — количество проверок до разрыва (CIS 5.1.7)
  - Banner — баннер перед входом (CIS 5.1.5)
"""

import os
import re


def check_ssh(reporter):
    config_path = "/etc/ssh/sshd_config"

    if not os.path.exists(config_path):
        reporter.add("CRITICAL", "SSH", "Файл sshd_config не найден. SSH-сервер, возможно, не установлен.")
        return

    with open(config_path, "r") as f:
        config = f.read()

    # PermitRootLogin (5.1.20, 2.1.2)
    match = re.search(r'^PermitRootLogin\s+(yes|no|prohibit-password|forced-commands-only)\s*$', config, re.MULTILINE)
    if not match:
        reporter.add("HIGH", "SSH", "PermitRootLogin не задан явно (по умолчанию может быть yes)", "5.1.20", "2.1.2")
    elif match.group(1) == "no":
        reporter.add("OK", "SSH", "PermitRootLogin = no", "5.1.20", "2.1.2")
    elif match.group(1) == "prohibit-password":
        reporter.add("OK", "SSH", "PermitRootLogin = prohibit-password", "5.1.20", "2.1.2")
    else:
        reporter.add("HIGH", "SSH", f"PermitRootLogin = {match.group(1)} (рекомендуется no)", "5.1.20", "2.1.2")

    # PermitEmptyPasswords (5.1.19)
    match = re.search(r'^PermitEmptyPasswords\s+(yes|no)\s*$', config, re.MULTILINE)
    if match and match.group(1) == "yes":
        reporter.add("CRITICAL", "SSH", "PermitEmptyPasswords = yes (разрешены пустые пароли!)", "5.1.19")
    elif match and match.group(1) == "no":
        reporter.add("OK", "SSH", "PermitEmptyPasswords = no", "5.1.19")

    # MaxAuthTries ≤ 4 (5.1.16)
    match = re.search(r'^MaxAuthTries\s+(\d+)\s*$', config, re.MULTILINE)
    if not match:
        reporter.add("MEDIUM", "SSH", "MaxAuthTries не задан (по умолчанию 6, рекомендуется ≤ 4)", "5.1.16")
    elif int(match.group(1)) <= 4:
        reporter.add("OK", "SSH", f"MaxAuthTries = {match.group(1)} (≤ 4)", "5.1.16")
    else:
        reporter.add("MEDIUM", "SSH", f"MaxAuthTries = {match.group(1)} (рекомендуется ≤ 4)", "5.1.16")

    # IgnoreRhosts = yes (5.1.11)
    match = re.search(r'^IgnoreRhosts\s+(yes|no)\s*$', config, re.MULTILINE)
    if not match:
        reporter.add("LOW", "SSH", "IgnoreRhosts не задан (рекомендуется yes)", "5.1.11")
    elif match.group(1) == "yes":
        reporter.add("OK", "SSH", "IgnoreRhosts = yes", "5.1.11")
    else:
        reporter.add("MEDIUM", "SSH", "IgnoreRhosts = no (рекомендуется yes)", "5.1.11")

    # HostbasedAuthentication = no (5.1.10)
    match = re.search(r'^HostbasedAuthentication\s+(yes|no)\s*$', config, re.MULTILINE)
    if not match:
        reporter.add("MEDIUM", "SSH", "HostbasedAuthentication не задан (рекомендуется no)", "5.1.10")
    elif match.group(1) == "no":
        reporter.add("OK", "SSH", "HostbasedAuthentication = no", "5.1.10")
    else:
        reporter.add("MEDIUM", "SSH", "HostbasedAuthentication = yes (рекомендуется no)", "5.1.10")

    # PermitUserEnvironment = no (5.1.21)
    match = re.search(r'^PermitUserEnvironment\s+(yes|no)\s*$', config, re.MULTILINE)
    if not match:
        reporter.add("LOW", "SSH", "PermitUserEnvironment не задан (рекомендуется no)", "5.1.21")
    elif match.group(1) == "no":
        reporter.add("OK", "SSH", "PermitUserEnvironment = no", "5.1.21")
    else:
        reporter.add("MEDIUM", "SSH", "PermitUserEnvironment = yes (рекомендуется no)", "5.1.21")

    # ClientAliveInterval (5.1.7)
    match = re.search(r'^ClientAliveInterval\s+(\d+)\s*$', config, re.MULTILINE)
    if match and int(match.group(1)) > 0:
        reporter.add("OK", "SSH", f"ClientAliveInterval = {match.group(1)} (настроен)", "5.1.7")
    else:
        reporter.add("LOW", "SSH", "ClientAliveInterval не задан или = 0", "5.1.7")

    # ClientAliveCountMax (5.1.7)
    match = re.search(r'^ClientAliveCountMax\s+(\d+)\s*$', config, re.MULTILINE)
    if match and int(match.group(1)) <= 3:
        reporter.add("OK", "SSH", f"ClientAliveCountMax = {match.group(1)}", "5.1.7")
    else:
        reporter.add("LOW", "SSH", "ClientAliveCountMax не задан (рекомендуется ≤ 3)", "5.1.7")

    # Banner (5.1.5)
    match = re.search(r'^Banner\s+(/\S+)\s*$', config, re.MULTILINE)
    if match:
        banner_path = match.group(1)
        if os.path.exists(banner_path):
            reporter.add("OK", "SSH", f"Баннер настроен: {banner_path}", "5.1.5")
        else:
            reporter.add("LOW", "SSH", f"Баннер указан ({banner_path}), но файл не найден", "5.1.5")
    else:
        reporter.add("LOW", "SSH", "Баннер не настроен", "5.1.5")