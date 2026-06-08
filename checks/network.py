"""
Модуль сетевого аудита и параметров ядра
(CIS Benchmarks + ФСТЭК)

Проверяемые параметры:
  СЕТЕВЫЕ ПОРТЫ:
    - Слушающие TCP-порты (CIS 2.1.22)
    - Подозрительные порты

  ПАРАМЕТРЫ SYSCLT (CIS):
    - net.ipv4.ip_forward = 0 (3.3.1)
    - accept_redirects = 0 (3.3.5)
    - accept_source_route = 0 (3.3.8)
    - icmp_echo_ignore_broadcasts = 1 (3.3.4)
    - icmp_ignore_bogus_error_responses = 1 (3.3.3)
    - rp_filter = 1 (3.3.7)
    - tcp_syncookies = 1 (3.3.10)
    - IPv6 accept_ra = 0 (3.3.11)

  ПАРАМЕТРЫ ФСТЭК:
    - kernel.dmesg_restrict = 1 (2.4.1)
    - kernel.kptr_restrict = 2 (2.4.2)
    - kernel.perf_event_paranoid = 3 (2.5.2)
    - kernel.kexec_load_disabled = 1 (2.5.4)
    - user.max_user_namespaces = 0 (2.5.5)
    - kernel.unprivileged_bpf_disabled = 1 (2.5.6)
    - vm.unprivileged_userfaultfd = 0 (2.5.7)
    - dev.tty.ldisc_autoload = 0 (2.5.8)
    - vm.mmap_min_addr = 4096 (2.5.10)
    - net.core.bpf_jit_harden = 2 (2.4.8)
    - fs.protected_symlinks = 1 (2.6.2)
    - fs.protected_hardlinks = 1 (2.6.3)
    - fs.protected_fifos = 2 (2.6.4)
    - fs.protected_regular = 2 (2.6.5)
    - fs.suid_dumpable = 0 (2.6.6)
    - kernel.yama.ptrace_scope = 3 (2.6.1)
    - kernel.randomize_va_space = 2 (2.5.11)

  ПРОЧЕЕ:
    - Bluetooth отключён (CIS 3.1.3)
    - Файрвол UFW/iptables (CIS 4.2.3)
    - Опции загрузки ядра: init_on_alloc, slab_nomerge, randomize_kstack_offset,
      vsyscall, debugfs, tsx, iommu, mitigations (ФСТЭК 2.4.3-2.4.7, 2.5.1, 2.5.3, 2.5.9)
"""

import subprocess
import re

SUSPICIOUS_PORTS = {
    "23": "Telnet", "21": "FTP", "135": "RPC", "139": "NetBIOS",
    "445": "SMB", "1433": "MS SQL", "3306": "MySQL", "5432": "PostgreSQL",
    "6379": "Redis", "27017": "MongoDB",
}

CIS_SYSCTL = {
    "net.ipv4.ip_forward": "3.3.1",
    "net.ipv4.conf.all.accept_redirects": "3.3.5",
    "net.ipv4.conf.all.accept_source_route": "3.3.8",
    "net.ipv4.icmp_echo_ignore_broadcasts": "3.3.4",
    "net.ipv4.icmp_ignore_bogus_error_responses": "3.3.3",
    "net.ipv4.conf.all.rp_filter": "3.3.7",
    "net.ipv4.tcp_syncookies": "3.3.10",
    "net.ipv6.conf.all.accept_ra": "3.3.11",
    "kernel.yama.ptrace_scope": "1.5.2",
    "kernel.randomize_va_space": "1.5.1",
    "fs.suid_dumpable": "1.5.3",
}

FSTEC_SYSCTL = {
    "net.ipv4.ip_forward": "",
    "net.ipv4.conf.all.accept_redirects": "",
    "net.ipv4.conf.all.accept_source_route": "",
    "net.ipv4.icmp_echo_ignore_broadcasts": "",
    "net.ipv4.icmp_ignore_bogus_error_responses": "",
    "net.ipv4.conf.all.rp_filter": "",
    "net.ipv4.tcp_syncookies": "",
    "net.ipv6.conf.all.accept_ra": "",
    "kernel.dmesg_restrict": "2.4.1",
    "kernel.kptr_restrict": "2.4.2",
    "kernel.perf_event_paranoid": "2.5.2",
    "kernel.kexec_load_disabled": "2.5.4",
    "user.max_user_namespaces": "2.5.5",
    "kernel.unprivileged_bpf_disabled": "2.5.6",
    "vm.unprivileged_userfaultfd": "2.5.7",
    "dev.tty.ldisc_autoload": "2.5.8",
    "vm.mmap_min_addr": "2.5.10",
    "net.core.bpf_jit_harden": "2.4.8",
    "fs.protected_symlinks": "2.6.2",
    "fs.protected_hardlinks": "2.6.3",
    "fs.protected_fifos": "2.6.4",
    "fs.protected_regular": "2.6.5",
    "fs.suid_dumpable": "2.6.6",
    "kernel.yama.ptrace_scope": "2.6.1",
    "kernel.randomize_va_space": "2.5.11",
}


def check_network(reporter):

    # Слушающие порты (2.1.22)
    cmd = "ss -tlnp 2>/dev/null"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        output = result.stdout
    except Exception as e:
        reporter.add("MEDIUM", "Network", f"Не удалось выполнить ss: {e}")
        output = ""

    lines = output.strip().split("\n")
    if len(lines) <= 1:
        reporter.add("OK", "Network", "Нет слушающих TCP-портов", "2.1.22")
    else:
        listening_ports = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[4]
            match = re.search(r':(\d+)$', local)
            if not match:
                continue
            port = match.group(1)
            process = "неизвестно"
            for part in parts:
                if '(' in part:
                    process = part.strip('()')
                    break
            listening_ports.append((port, process))

        reporter.add("LOW", "Network", f"Слушающих TCP-портов: {len(listening_ports)}", "2.1.22")
        for port, process in listening_ports:
            if port in SUSPICIOUS_PORTS:
                reporter.add("MEDIUM", "Network", f"Порт {port} ({SUSPICIOUS_PORTS[port]}) — {process}", "2.1.22")
            else:
                reporter.add("OK", "Network", f"Порт {port} — {process}", "2.1.22")

    # Параметры sysctl
    sysctl_checks = [
        # CIS
        ("net.ipv4.ip_forward", "0", "HIGH", "IP forwarding включён", "IP forwarding выключен"),
        ("net.ipv4.conf.all.accept_redirects", "0", "MEDIUM", "ICMP-редиректы включены", "ICMP-редиректы выключены"),
        ("net.ipv4.conf.all.accept_source_route", "0", "HIGH", "Source routed packets принимаются", "Source routed packets не принимаются"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "MEDIUM", "ICMP broadcast не игнорируются", "ICMP broadcast игнорируются"),
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "MEDIUM", "Bogus ICMP не фильтруются", "Bogus ICMP фильтруются"),
        ("net.ipv4.conf.all.rp_filter", "1", "MEDIUM", "Reverse Path Filtering выключен", "Reverse Path Filtering включён"),
        ("net.ipv4.tcp_syncookies", "1", "HIGH", "TCP SYN Cookies выключены", "TCP SYN Cookies включены"),
        ("net.ipv6.conf.all.accept_ra", "0", "MEDIUM", "IPv6 RA принимаются", "IPv6 RA не принимаются"),
        # ФСТЭК
        ("kernel.dmesg_restrict", "1", "LOW", "dmesg доступен пользователям", "dmesg ограничен"),
        ("kernel.kptr_restrict", "2", "LOW", "Указатели ядра доступны", "Указатели ядра скрыты"),
        ("kernel.perf_event_paranoid", "3", "MEDIUM", "События производительности доступны", "События производительности ограничены"),
        ("kernel.kexec_load_disabled", "1", "MEDIUM", "kexec_load разрешён", "kexec_load запрещён"),
        ("user.max_user_namespaces", "0", "LOW", "User namespaces не запрещены", "User namespaces запрещены"),
        ("kernel.unprivileged_bpf_disabled", "1", "MEDIUM", "BPF для непривилегированных не запрещён", "BPF для непривилегированных запрещён"),
        ("vm.unprivileged_userfaultfd", "0", "LOW", "userfaultfd для непривилегированных разрешён", "userfaultfd для непривилегированных запрещён"),
        ("dev.tty.ldisc_autoload", "0", "LOW", "ldisc_autoload включён", "ldisc_autoload выключен"),
        ("vm.mmap_min_addr", None, "MEDIUM", "mmap_min_addr меньше 4096", "mmap_min_addr >= 4096"),
        ("net.core.bpf_jit_harden", "2", "MEDIUM", "bpf_jit_harden не включён", "bpf_jit_harden = 2"),
        ("fs.protected_symlinks", "1", "MEDIUM", "Защита symlink ослаблена", "Защита symlink включена"),
        ("fs.protected_hardlinks", "1", "MEDIUM", "Защита hardlink ослаблена", "Защита hardlink включена"),
        ("fs.protected_fifos", "2", "MEDIUM", "Защита FIFO ослаблена", "Защита FIFO включена"),
        ("fs.protected_regular", "2", "MEDIUM", "Защита regular файлов ослаблена", "Защита regular файлов включена"),
        ("fs.suid_dumpable", "0", "MEDIUM", "SUID-дампы разрешены", "SUID-дампы запрещены"),
        ("kernel.yama.ptrace_scope", "3", "MEDIUM", "ptrace_scope не равен 3 (рекомендация ФСТЭК)", "ptrace_scope = 3"),
        ("kernel.randomize_va_space", "2", "HIGH", "ASLR выключен", "ASLR включён"),
    ]

    for param, expected, severity, bad_msg, ok_msg in sysctl_checks:
        cis_code = CIS_SYSCTL.get(param, "")
        fstec_code = FSTEC_SYSCTL.get(param, "")
        try:
            with open(f"/proc/sys/{param.replace('.', '/')}", "r") as f:
                value = f.read().strip()
            # Особая проверка для mmap_min_addr (>= 4096)
            if param == "vm.mmap_min_addr":
                if int(value) >= 4096:
                    reporter.add("OK", "Network", ok_msg, cis_code, fstec_code)
                else:
                    reporter.add(severity, "Network", f"{bad_msg} (текущее: {value})", cis_code, fstec_code)
            else:
                if value == expected:
                    reporter.add("OK", "Network", ok_msg, cis_code, fstec_code)
                else:
                    reporter.add(severity, "Network", f"{bad_msg} (текущее: {value})", cis_code, fstec_code)
        except FileNotFoundError:
            reporter.add("LOW", "Network", f"Параметр {param} не найден", cis_code, fstec_code)
        except PermissionError:
            reporter.add("LOW", "Network", f"Нет доступа к {param}", cis_code, fstec_code)

    # Bluetooth (3.1.3)
    cmd = "systemctl is-active bluetooth 2>/dev/null"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stdout.strip() == "active":
            reporter.add("MEDIUM", "Network", "Bluetooth активен", "3.1.3")
        else:
            reporter.add("OK", "Network", "Bluetooth отключён", "3.1.3")
    except Exception:
        reporter.add("LOW", "Network", "Не удалось проверить Bluetooth", "3.1.3")

    # Firewall (4.2.3)
    cmd = "systemctl is-active ufw 2>/dev/null"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stdout.strip() == "active":
            reporter.add("OK", "Network", "UFW активен", "4.2.3")
        else:
            cmd2 = "systemctl is-active iptables 2>/dev/null"
            result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)
            if result2.stdout.strip() == "active":
                reporter.add("OK", "Network", "iptables активен", "4.2.3")
            else:
                reporter.add("HIGH", "Network", "Файрвол не активен (ни UFW, ни iptables)", "4.2.3")
    except Exception:
        reporter.add("LOW", "Network", "Не удалось проверить файрвол", "4.2.3")

    # === ФСТЭК 2.4.3: init_on_alloc ===
    _check_kernel_cmdline(reporter, "init_on_alloc=1", "init_on_alloc=1", "2.4.3",
                          "init_on_alloc не установлен в cmdline", "init_on_alloc=1 в cmdline")

    # === ФСТЭК 2.4.4: slab_nomerge ===
    _check_kernel_cmdline(reporter, "slab_nomerge", "slab_nomerge", "2.4.4",
                          "slab_nomerge не установлен в cmdline", "slab_nomerge в cmdline")

    # === ФСТЭК 2.4.6: randomize_kstack_offset ===
    _check_kernel_cmdline(reporter, "randomize_kstack_offset=1", "randomize_kstack_offset=1", "2.4.6",
                          "randomize_kstack_offset=1 не установлен", "randomize_kstack_offset=1 установлен")

    # === ФСТЭК 2.4.7: mitigations ===
    _check_kernel_cmdline(reporter, "mitigations=auto", "mitigations=auto,nosmt", "2.4.7",
                          "mitigations не настроены", "mitigations настроены")

    # === ФСТЭК 2.5.1: vsyscall=none ===
    _check_kernel_cmdline(reporter, "vsyscall=none", "vsyscall=none", "2.5.1",
                          "vsyscall не none", "vsyscall=none установлен")

    # === ФСТЭК 2.5.3: debugfs=no-mount ===
    _check_kernel_cmdline(reporter, "debugfs=no-mount", "debugfs=no-mount", "2.5.3",
                          "debugfs монтируется", "debugfs=no-mount установлен")

    # === ФСТЭК 2.5.9: tsx=off ===
    _check_kernel_cmdline_any(reporter, ["tsx=off", "tsx_async_abort=full"], "tsx=off", "2.5.9",
                              "tsx не отключён", "tsx отключён")

    # === ФСТЭК 2.4.5: IOMMU ===
    _check_kernel_cmdline_all(reporter, ["iommu=force", "iommu.strict=1", "iommu.passthrough=0"],
                              "iommu", "2.4.5", "IOMMU не настроен", "IOMMU настроен")


def _check_kernel_cmdline(reporter, search, expect, fstec, bad, ok_msg):
    """Проверка опции загрузки ядра в /proc/cmdline."""
    try:
        with open("/proc/cmdline", "r") as f:
            cmdline = f.read()
        if search in cmdline:
            reporter.add("OK", "Network", ok_msg, "", fstec)
        else:
            reporter.add("LOW", "Network", bad, "", fstec)
    except Exception:
        reporter.add("LOW", "Network", f"Не удалось проверить {expect}", "", fstec)


def _check_kernel_cmdline_any(reporter, options, expect, fstec, bad, ok_msg):
    """Проверка: хотя бы одна из опций присутствует."""
    try:
        with open("/proc/cmdline", "r") as f:
            cmdline = f.read()
        if any(opt in cmdline for opt in options):
            reporter.add("OK", "Network", ok_msg, "", fstec)
        else:
            reporter.add("LOW", "Network", bad, "", fstec)
    except Exception:
        reporter.add("LOW", "Network", f"Не удалось проверить {expect}", "", fstec)


def _check_kernel_cmdline_all(reporter, options, expect, fstec, bad, ok_msg):
    """Проверка: все опции присутствуют."""
    try:
        with open("/proc/cmdline", "r") as f:
            cmdline = f.read()
        missing = [opt for opt in options if opt not in cmdline]
        if not missing:
            reporter.add("OK", "Network", ok_msg, "", fstec)
        else:
            reporter.add("LOW", "Network", f"{bad} (отсутствуют: {', '.join(missing)})", "", fstec)
    except Exception:
        reporter.add("LOW", "Network", f"Не удалось проверить {expect}", "", fstec)