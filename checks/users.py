"""
Модуль аудита учётных записей и парольной политики
(CIS Benchmarks + ФСТЭК)

Проверяемые параметры:
  - UID 0 только у root (CIS 5.4.2.1)
  - Пустые пароли (CIS 7.2.2, ФСТЭК 2.1.1)
  - TMOUT (CIS 5.4.3.2)
  - Блокировка после неудачных попыток (CIS 5.3.3.1.1)
  - Минимальная длина пароля (CIS 5.3.3.2.2)
  - su ограничен группой wheel (CIS 5.2.7, ФСТЭК 2.2.1)
  - PASS_MAX_DAYS (CIS 5.4.1.1)
  - PASS_MIN_DAYS (CIS 5.4.1.2)
  - Уникальность UID (CIS 7.2.5)
  - Права домашних директорий (ФСТЭК 2.3.11)
  - Права файлов в домашних директориях (ФСТЭК 2.3.10)
  - Аудит /etc/sudoers (ФСТЭК 2.2.2)
"""

import os
import re
import stat


def check_users(reporter):

    # UID 0 только у root (5.4.2.1)
    try:
        with open("/etc/passwd", "r") as f:
            passwd_lines = f.readlines()
    except FileNotFoundError:
        reporter.add("CRITICAL", "Users", "Файл /etc/passwd не найден")
        return

    root_accounts = []
    for line in passwd_lines:
        parts = line.strip().split(":")
        if len(parts) >= 3:
            username = parts[0]
            uid = parts[2]
            if uid == "0":
                root_accounts.append(username)

    if root_accounts == ["root"]:
        reporter.add("OK", "Users", "UID 0 есть только у root", "5.4.2.1")
    else:
        for user in root_accounts:
            if user != "root":
                reporter.add("CRITICAL", "Users", f"Пользователь {user} имеет UID 0!", "5.4.2.1")

    # Пустые пароли (7.2.2, 2.1.1)
    try:
        with open("/etc/shadow", "r") as f:
            shadow_lines = f.readlines()
    except FileNotFoundError:
        reporter.add("HIGH", "Users", "Файл /etc/shadow не найден")
        return

    empty_password_users = []
    locked_users = []

    for line in shadow_lines:
        parts = line.strip().split(":")
        if len(parts) >= 2:
            username = parts[0]
            password_hash = parts[1]

            if password_hash == "":
                empty_password_users.append(username)
            if password_hash.startswith("!") or password_hash.startswith("*"):
                locked_users.append(username)

    if empty_password_users:
        for user in empty_password_users:
            reporter.add("CRITICAL", "Users", f"Пустой пароль у пользователя {user}", "7.2.2", "2.1.1")
    else:
        reporter.add("OK", "Users", "Пустые пароли отсутствуют", "7.2.2", "2.1.1")

    if locked_users:
        reporter.add("LOW", "Users", f"Заблокировано учёток: {len(locked_users)}")
    else:
        reporter.add("OK", "Users", "Нет заблокированных учётных записей")

    # TMOUT (5.4.3.2)
    tmout_found = False
    for profile_file in ["/etc/profile", "/etc/bash.bashrc", "/etc/profile.d/autologout.sh"]:
        if os.path.exists(profile_file):
            with open(profile_file, "r") as f:
                content = f.read()
            match = re.search(r'(readonly\s+)?TMOUT=\s*(\d+)', content)
            if match:
                reporter.add("OK", "Users", f"TMOUT задан: {match.group(2)} сек", "5.4.3.2")
                tmout_found = True
                break
    if not tmout_found:
        reporter.add("MEDIUM", "Users", "TMOUT не задан (сессии не закрываются)", "5.4.3.2")

    # Блокировка после неудачных попыток (5.3.3.1.1)
    pam_files = ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]
    lockout_found = False
    for pam_file in pam_files:
        if os.path.exists(pam_file):
            with open(pam_file, "r") as f:
                content = f.read()
            if "pam_faillock.so" in content or "pam_tally2.so" in content or "pam_tally.so" in content:
                reporter.add("OK", "Users", "Блокировка после неудачных попыток настроена", "5.3.3.1.1")
                lockout_found = True
                break
    if not lockout_found:
        reporter.add("HIGH", "Users", "Блокировка после неудачных попыток НЕ настроена", "5.3.3.1.1")

    # Минимальная длина пароля (5.3.3.2.2)
    pwquality_found = False
    for path in ["/etc/security/pwquality.conf", "/etc/pam.d/common-password"]:
        if os.path.exists(path):
            with open(path, "r") as f:
                content = f.read()
            match = re.search(r'minlen\s*=\s*(\d+)', content)
            if match:
                minlen = int(match.group(1))
                if minlen >= 14:
                    reporter.add("OK", "Users", f"Минимальная длина пароля: {minlen} (≥14)", "5.3.3.2.2")
                else:
                    reporter.add("HIGH", "Users", f"Минимальная длина пароля: {minlen} (рекомендуется ≥ 14)", "5.3.3.2.2")
                pwquality_found = True
                break
    if not pwquality_found:
        reporter.add("MEDIUM", "Users", "Минимальная длина пароля не настроена", "5.3.3.2.2")

    # su через wheel (5.2.7, 2.2.1)
    if os.path.exists("/etc/pam.d/su"):
        with open("/etc/pam.d/su", "r") as f:
            su_content = f.read()
        if "pam_wheel.so" in su_content:
            reporter.add("OK", "Users", "su ограничен группой wheel", "5.2.7", "2.2.1")
        else:
            reporter.add("MEDIUM", "Users", "su не ограничен (любой может стать root)", "5.2.7", "2.2.1")

    # Password aging (5.4.1.1, 5.4.1.2)
    if os.path.exists("/etc/login.defs"):
        with open("/etc/login.defs", "r") as f:
            login_defs = f.read()
        match = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
        if match:
            max_days = int(match.group(1))
            if max_days <= 90:
                reporter.add("OK", "Users", f"Максимальный срок пароля: {max_days} дней", "5.4.1.1")
            else:
                reporter.add("MEDIUM", "Users", f"Максимальный срок пароля: {max_days} дней (рекомендуется ≤ 90)", "5.4.1.1")

        match = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
        if match:
            min_days = int(match.group(1))
            if min_days >= 1:
                reporter.add("OK", "Users", f"Минимальный срок до смены пароля: {min_days} дней", "5.4.1.2")
            else:
                reporter.add("LOW", "Users", f"Минимальный срок до смены пароля: {min_days} (рекомендуется ≥ 1)", "5.4.1.2")

    # Unique UID (7.2.5)
    uids = []
    for line in passwd_lines:
        parts = line.strip().split(":")
        if len(parts) >= 3:
            uids.append(parts[2])
    if len(uids) == len(set(uids)):
        reporter.add("OK", "Users", "UID пользователей уникальны", "7.2.5")
    else:
        reporter.add("WARNING", "Users", "Обнаружены дублирующиеся UID", "7.2.5")

    # Аудит /etc/sudoers (2.2.2)
    sudoers_files = ["/etc/sudoers"]
    if os.path.exists("/etc/sudoers.d"):
        for f in os.listdir("/etc/sudoers.d"):
            if f.endswith("~") or f.startswith("."):
                continue
            sudoers_files.append(f"/etc/sudoers.d/{f}")

    nopasswd_found = False
    for sf in sudoers_files:
        if os.path.exists(sf):
            with open(sf, "r") as f:
                content = f.read()
            if re.search(r'NOPASSWD', content):
                nopasswd_found = True
                reporter.add("HIGH", "Users", f"Обнаружен NOPASSWD в {sf} (sudo без пароля)", "", "2.2.2")

    if not nopasswd_found and len(sudoers_files) > 0:
        reporter.add("OK", "Users", "NOPASSWD в sudoers не обнаружен", "", "2.2.2")

    # Права домашних директорий (2.3.11)
    shells = ["/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash"]
    home_issues = []
    for line in passwd_lines:
        parts = line.strip().split(":")
        if len(parts) >= 7:
            username = parts[0]
            shell = parts[6]
            home = parts[5]
            if shell in shells and os.path.exists(home):
                try:
                    home_stat = os.stat(home)
                    home_mode = stat.S_IMODE(home_stat.st_mode)
                    if home_mode & 0o077:  # группа или другие имеют доступ
                        home_issues.append(f"{username}:{home}")
                except Exception:
                    pass

    if home_issues:
        reporter.add("MEDIUM", "Users", f"Домашние директории с доступом для группы/других: {len(home_issues)}", "", "2.3.11")
    else:
        reporter.add("OK", "Users", "Домашние директории имеют корректные права", "", "2.3.11")

    # Права файлов в домашних директориях (2.3.10)
    sensitive_files = [".bash_history", ".history", ".sh_history", ".bash_profile", ".bashrc", ".profile", ".bash_logout", ".rhosts"]
    dotfile_issues = 0
    for line in passwd_lines:
        parts = line.strip().split(":")
        if len(parts) >= 7:
            home = parts[5]
            shell = parts[6]
            if shell in shells and os.path.exists(home):
                for sf in sensitive_files:
                    sf_path = os.path.join(home, sf)
                    if os.path.exists(sf_path):
                        try:
                            sf_stat = os.stat(sf_path)
                            sf_mode = stat.S_IMODE(sf_stat.st_mode)
                            if sf_mode & 0o077:
                                dotfile_issues += 1
                        except Exception:
                            pass

    if dotfile_issues > 0:
        reporter.add("MEDIUM", "Users", f"Файлов в домашних директориях с доступом группы/других: {dotfile_issues}", "", "2.3.10")
    else:
        reporter.add("OK", "Users", "Файлы в домашних директориях имеют корректные права", "", "2.3.10")