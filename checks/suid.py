"""
Модуль поиска SUID/SGID-файлов
(CIS Benchmarks 7.1.13)

Проверяемые параметры:
  - Общее количество SUID/SGID-файлов в системе
  - Наличие подозрительных SUID-файлов, которые могут быть
    использованы для повышения привилегий (Privilege Escalation)

Список подозрительных файлов (нештатные SUID):
  Редакторы: vim, vi, nano, less, more, man
  Оболочки: bash, sh, dash, zsh
  Интерпретаторы: python, python3, perl, ruby, lua
  Утилиты: find, grep, awk, sed, nmap
  Файловые операции: cp, mv, cat, tee
  Права: chmod, chown
  Системные: systemctl, journalctl
  Планировщик: at
  Сетевые: ssh, scp, sftp, wget, curl
  Кодирование/шифрование: xxd, base64
  Отладка: gdb, strace
  Терминальные: screen, tmux
  Контейнеры: docker, lxc, lxd

  Штатные SUID (/usr/bin/su, /usr/bin/sudo, /usr/bin/passwd,
  /usr/bin/mount, /usr/bin/umount, /usr/bin/pkexec, /usr/bin/crontab)
  исключены из списка подозрительных.
"""

import subprocess


SUSPICIOUS_SUID = [
    "vim", "vi", "nano", "less", "more", "man",      # редакторы
    "find", "bash", "sh", "dash", "zsh",               # оболочки
    "python", "python3", "perl", "ruby", "lua",        # интерпретаторы
    "awk", "sed", "grep", "nmap",                      # утилиты
    "cp", "mv", "cat", "tee",                          # файловые операции
    "chmod", "chown",                                   # права
    "systemctl", "journalctl",                          # системные
    "ssh", "scp", "sftp", "wget", "curl",              # сетевые
    "xxd", "base64", "gdb", "strace",                  # отладка
    "screen", "tmux", "docker", "lxc", "lxd",          # контейнеры
]


def check_suid(reporter):
    cmd = (
        "find / -type f "
        "-not -path '/proc/*' "
        "-not -path '/sys/*' "
        "-not -path '/snap/*' "
        "\\( -perm -4000 -o -perm -2000 \\) "
        "-ls 2>/dev/null"
    )

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        lines = result.stdout.strip().split("\n")
    except subprocess.TimeoutExpired:
        reporter.add("MEDIUM", "SUID", "Поиск SUID занял слишком много времени", "7.1.13")
        return
    except Exception as e:
        reporter.add("MEDIUM", "SUID", f"Ошибка поиска SUID: {e}", "7.1.13")
        return

    if not lines or lines == [""]:
        reporter.add("OK", "SUID", "SUID/SGID-файлы не найдены", "7.1.13")
        return

    all_suid = []
    suspicious_found = []

    for line in lines:
        parts = line.split()
        if len(parts) < 11:
            continue
        filepath = parts[10]
        if filepath.endswith("/"):
            continue
        all_suid.append(filepath)
        filename = filepath.split("/")[-1]
        if filename in SUSPICIOUS_SUID:
            suspicious_found.append(filepath)

    reporter.add("LOW", "SUID", f"Всего SUID/SGID-файлов: {len(all_suid)}", "7.1.13", "2.3.9")

    if suspicious_found:
        for f in suspicious_found:
            reporter.add("HIGH", "SUID", f"Подозрительный SUID-файл: {f}", "7.1.13")
    else:
        reporter.add("OK", "SUID", "Подозрительных SUID-файлов не найдено", "7.1.13")