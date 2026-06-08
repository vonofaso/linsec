"""
Модуль проверки прав доступа, служб и системных параметров
(CIS Benchmarks + ФСТЭК)

Проверяемые параметры:
  ПРАВА НА ФАЙЛЫ:
    - /etc/shadow (CIS 7.1.5, ФСТЭК 2.3.1)
    - /etc/passwd (CIS 7.1.1, ФСТЭК 2.3.1)
    - /etc/group (CIS 7.1.3, ФСТЭК 2.3.1)
    - /etc/gshadow (CIS 7.1.7)
    - /etc/crontab (CIS 2.4.1.2, ФСТЭК 2.3.6)
    - cron.hourly/daily/weekly/monthly (CIS 2.4.1.3-2.4.1.6, ФСТЭК 2.3.6)

  СИСТЕМНЫЕ ПАРАМЕТРЫ:
    - Sticky-бит на /tmp (CIS 7.1.11)
    - Пароль на GRUB (CIS 1.4.1)
    - usb-storage заблокирован (CIS 1.1.1.9)
    - AppArmor активен (CIS 1.3.1.1)

  НЕБЕЗОПАСНЫЕ СЛУЖБЫ:
    - FTP отключён (CIS 2.1.6)
    - Samba отключена (CIS 2.1.14)
    - NFS отключён (CIS 2.1.9)
    - rsync демон отключён (CIS 2.1.13)
    - NIS отключён (CIS 2.1.10)
    - rsh отключён (CIS 2.2.2)

  ПРОЧЕЕ:
    - Теневые пароли (CIS 7.2.1)
    - World-writable файлы (CIS 7.1.11)
    - CUPS отключён (CIS 2.1.11)

  ФСТЭК:
    - Права на sudo-файлы (2.3.4)
    - Права на стартовые скрипты (2.3.5)
    - Права на пользовательские cron (2.3.7)
    - Права на /bin, /usr/bin, /lib (2.3.8)
"""

import os
import stat
import subprocess
import glob


CIS_FILE_PERMS = {
    "/etc/shadow": "7.1.5",
    "/etc/passwd": "7.1.1",
    "/etc/group": "7.1.3",
    "/etc/gshadow": "7.1.7",
    "/etc/crontab": "2.4.1.2",
    "/etc/cron.hourly": "2.4.1.3",
    "/etc/cron.daily": "2.4.1.4",
    "/etc/cron.weekly": "2.4.1.5",
    "/etc/cron.monthly": "2.4.1.6",
}

FSTEC_FILE_PERMS = {
    "/etc/shadow": "2.3.1",
    "/etc/passwd": "2.3.1",
    "/etc/group": "2.3.1",
    "/etc/crontab": "2.3.6",
    "/etc/cron.hourly": "2.3.6",
    "/etc/cron.daily": "2.3.6",
    "/etc/cron.weekly": "2.3.6",
    "/etc/cron.monthly": "2.3.6",
}

CIS_SERVICES = {
    "FTP": "2.1.6",
    "Samba (SMB)": "2.1.14",
    "NFS": "2.1.9",
    "rsync демон": "2.1.13",
    "NIS": "2.1.10",
    "rsh": "2.2.2",
}


def check_files(reporter):

    # Права на критические файлы
    critical_files = [
        ("/etc/shadow", "640", "root", "Файл теневых паролей"),
        ("/etc/passwd", "644", "root", "Файл учётных записей"),
        ("/etc/group", "644", "root", "Файл групп"),
        ("/etc/gshadow", "640", "root", "Теневой файл групп"),
        ("/etc/crontab", "600", "root", "Системный crontab"),
        ("/etc/cron.hourly", "700", "root", "Директория cron.hourly"),
        ("/etc/cron.daily", "700", "root", "Директория cron.daily"),
        ("/etc/cron.weekly", "700", "root", "Директория cron.weekly"),
        ("/etc/cron.monthly", "700", "root", "Директория cron.monthly"),
    ]

    for path, expected_perms, expected_owner, description in critical_files:
        cis_code = CIS_FILE_PERMS.get(path, "")
        fstec_code = FSTEC_FILE_PERMS.get(path, "")
        if not os.path.exists(path):
            reporter.add("LOW", "Files", f"{description} ({path}) не найден", cis_code, fstec_code)
            continue

        try:
            file_stat = os.stat(path)
        except PermissionError:
            reporter.add("MEDIUM", "Files", f"Нет доступа к {description} ({path})", cis_code, fstec_code)
            continue

        actual_perms = oct(stat.S_IMODE(file_stat.st_mode))[2:].zfill(3)
        if actual_perms != expected_perms:
            reporter.add("HIGH", "Files", f"{description} ({path}): права {actual_perms}, ожидалось {expected_perms}", cis_code, fstec_code)

        try:
            import pwd
            actual_owner = pwd.getpwuid(file_stat.st_uid).pw_name
        except (ImportError, KeyError):
            actual_owner = str(file_stat.st_uid)

        if actual_owner != expected_owner:
            reporter.add("HIGH", "Files", f"{description} ({path}): владелец {actual_owner}, ожидался {expected_owner}", cis_code, fstec_code)

    # Sticky-бит /tmp (7.1.11)
    if os.path.exists("/tmp"):
        tmp_stat = os.stat("/tmp")
        if tmp_stat.st_mode & stat.S_ISVTX:
            reporter.add("OK", "Files", "Sticky-бит на /tmp установлен", "7.1.11")
        else:
            reporter.add("HIGH", "Files", "Sticky-бит на /tmp НЕ установлен", "7.1.11")

    # GRUB password (1.4.1)
    if os.path.exists("/boot/grub/grub.cfg"):
        with open("/boot/grub/grub.cfg", "r") as f:
            grub_cfg = f.read()
        if "password_pbkdf2" in grub_cfg and "superusers" in grub_cfg:
            reporter.add("OK", "Files", "Пароль на GRUB установлен", "1.4.1")
        else:
            reporter.add("HIGH", "Files", "Пароль на загрузчик GRUB не установлен", "1.4.1")

    # USB-storage (1.1.1.9)
    blacklist_paths = ["/etc/modprobe.d/blacklist.conf", "/etc/modprobe.d/blacklist-usb-storage.conf"]
    usb_blocked = False
    for bp in blacklist_paths:
        if os.path.exists(bp):
            with open(bp, "r") as f:
                if "blacklist usb-storage" in f.read():
                    reporter.add("OK", "Files", "Модуль usb-storage заблокирован", "1.1.1.9")
                    usb_blocked = True
                    break
    if not usb_blocked:
        reporter.add("MEDIUM", "Files", "Модуль usb-storage не заблокирован (USB-накопители разрешены)", "1.1.1.9")

    # AppArmor (1.3.1.1)
    cmd = "aa-status 2>/dev/null"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if "apparmor module is loaded" in result.stdout or "profiles are loaded" in result.stdout:
            reporter.add("OK", "Files", "AppArmor активен", "1.3.1.1")
        else:
            reporter.add("MEDIUM", "Files", "AppArmor не активен", "1.3.1.1")
    except Exception:
        reporter.add("LOW", "Files", "Не удалось проверить AppArmor", "1.3.1.1")

    # Небезопасные службы
    dangerous_services = [
        ("telnetd", "Telnet"),
        ("vsftpd", "FTP"),
        ("smbd", "Samba (SMB)"),
        ("nfs-kernel-server", "NFS"),
        ("rsync", "rsync демон"),
        ("ypserv", "NIS"),
        ("rsh-server", "rsh"),
    ]
    # Сопоставление служба → пакет
    service_packages = {
        "telnetd": "telnetd",
        "vsftpd": "vsftpd",
        "smbd": "samba",
        "nfs-kernel-server": "nfs-kernel-server",
        "rsync": "rsync",
        "ypserv": "ypserv",
        "rsh-server": "rsh-server",
    }
    for svc, desc in dangerous_services:
        cis_code = CIS_SERVICES.get(desc, "")
        pkg = service_packages.get(svc, svc)

        # Проверка установки пакета (CIS)
        cmd_pkg = f"dpkg-query -s {pkg} 2>/dev/null"
        try:
            result_pkg = subprocess.run(cmd_pkg, shell=True, capture_output=True, text=True)
            pkg_installed = "install ok installed" in result_pkg.stdout
        except Exception:
            pkg_installed = False

        # Проверка активности службы
        cmd = f"systemctl is-active {svc} 2>/dev/null"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            status = result.stdout.strip()
        except Exception:
            status = "unknown"

        if not pkg_installed:
            reporter.add("OK", "Files", f"{desc}: пакет не установлен", cis_code)
        elif status == "inactive":
            reporter.add("OK", "Files", f"{desc} отключён (пакет есть, служба остановлена)", cis_code)
        elif status == "active":
            reporter.add("HIGH", "Files", f"{desc} активен! (рекомендуется отключить)", cis_code)
        else:
            reporter.add("LOW", "Files", f"{desc}: пакет установлен, служба не найдена", cis_code)

    # Теневые пароли (7.2.1)
    try:
        with open("/etc/passwd", "r") as f:
            passwd_content = f.readlines()
        shadow_ok = True
        for line in passwd_content:
            parts = line.strip().split(":")
            if len(parts) >= 2 and parts[1] not in ("x", ""):
                reporter.add("CRITICAL", "Files", f"Пароль пользователя {parts[0]} в /etc/passwd!", "7.2.1")
                shadow_ok = False
                break
        if shadow_ok:
            reporter.add("OK", "Files", "Теневые пароли используются (shadow)", "7.2.1")
    except FileNotFoundError:
        pass

    # World-writable файлы (7.1.11)
    cmd = "find / -type f -perm -o+w -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | wc -l"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        count = int(result.stdout.strip())
        if count == 0:
            reporter.add("OK", "Files", "Нет world-writable файлов", "7.1.11")
        else:
            reporter.add("MEDIUM", "Files", f"Найдено world-writable файлов: {count}", "7.1.11")
    except Exception:
        reporter.add("LOW", "Files", "Не удалось проверить world-writable файлы", "7.1.11")

    # CUPS (2.1.11)
    cmd = "systemctl is-active cups 2>/dev/null"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stdout.strip() == "active":
            reporter.add("MEDIUM", "Files", "CUPS активен (рекомендуется отключить на сервере)", "2.1.11")
        else:
            reporter.add("OK", "Files", "CUPS отключён", "2.1.11")
    except Exception:
        reporter.add("LOW", "Files", "Не удалось проверить CUPS", "2.1.11")

    # === ФСТЭК 2.3.4: Права на sudo-файлы ===
    sudo_files = []
    for sf in ["/etc/sudoers"]:
        if os.path.exists(sf):
            sudo_files.append(sf)
    if os.path.exists("/etc/sudoers.d"):
        for f in os.listdir("/etc/sudoers.d"):
            fp = f"/etc/sudoers.d/{f}"
            if os.path.isfile(fp) and not f.endswith("~") and not f.startswith("."):
                sudo_files.append(fp)

    sudo_issues = 0
    for sf in sudo_files:
        try:
            sf_stat = os.stat(sf)
            sf_mode = stat.S_IMODE(sf_stat.st_mode)
            if sf_mode & 0o022:
                sudo_issues += 1
                reporter.add("HIGH", "Files", f"Файл {sf} доступен на запись группе/другим", "", "2.3.4")
        except Exception:
            pass
    if sudo_issues == 0:
        reporter.add("OK", "Files", "Права на sudo-файлы корректны", "", "2.3.4")

    # === ФСТЭК 2.3.5: Права на стартовые скрипты ===
    rc_issues = 0
    for rc_dir in ["/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d"]:
        if os.path.exists(rc_dir):
            for f in os.listdir(rc_dir):
                fp = os.path.join(rc_dir, f)
                if os.path.isfile(fp):
                    try:
                        fm = stat.S_IMODE(os.stat(fp).st_mode)
                        if fm & 0o002:
                            rc_issues += 1
                    except Exception:
                        pass

    service_issues = 0
    for sd in ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]:
        if os.path.exists(sd):
            for f in glob.glob(f"{sd}/*.service"):
                try:
                    fm = stat.S_IMODE(os.stat(f).st_mode)
                    if fm & 0o002:
                        service_issues += 1
                except Exception:
                    pass

    total_rc = rc_issues + service_issues
    if total_rc == 0:
        reporter.add("OK", "Files", "Права на стартовые скрипты корректны", "", "2.3.5")
    else:
        reporter.add("MEDIUM", "Files", f"Стартовых скриптов с доступом на запись другим: {total_rc}", "", "2.3.5")

    # === ФСТЭК 2.3.7: Права на пользовательские cron ===
    cron_dirs = ["/var/spool/cron/crontabs", "/var/spool/cron"]
    user_cron_issues = 0
    for cd in cron_dirs:
        if os.path.exists(cd):
            for root, dirs, files in os.walk(cd):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        fm = stat.S_IMODE(os.stat(fp).st_mode)
                        if fm & 0o077:
                            user_cron_issues += 1
                    except Exception:
                        pass
    if user_cron_issues == 0:
        reporter.add("OK", "Files", "Права на пользовательские cron корректны", "", "2.3.7")
    else:
        reporter.add("MEDIUM", "Files", f"Пользовательских cron-файлов с небезопасными правами: {user_cron_issues}", "", "2.3.7")

    # === ФСТЭК 2.3.8: Права на /bin, /usr/bin, /lib ===
    bin_issues = 0
    for check_dir in ["/bin", "/usr/bin", "/lib", "/lib64"]:
        if os.path.exists(check_dir):
            for f in glob.glob(f"{check_dir}/*"):
                if os.path.isfile(f):
                    try:
                        fm = stat.S_IMODE(os.stat(f).st_mode)
                        if fm & 0o022:
                            bin_issues += 1
                    except Exception:
                        pass

    if bin_issues == 0:
        reporter.add("OK", "Files", "Права на файлы в /bin, /usr/bin, /lib корректны", "", "2.3.8")
    else:
        reporter.add("MEDIUM", "Files", f"Файлов в /bin, /usr/bin, /lib с небезопасными правами: {bin_issues}", "", "2.3.8")
