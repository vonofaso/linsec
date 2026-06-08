import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reporter import Reporter
from checks.sshd import check_ssh
from checks.users import check_users
from checks.files import check_files
from checks.suid import check_suid
from checks.network import check_network


def main():
    reporter = Reporter()

    print("[*] Запуск LinSec — Linux Security Auditor")
    print("[*] Начинаем проверки...\n")

    check_ssh(reporter)
    check_users(reporter)
    check_files(reporter)
    check_suid(reporter)
    check_network(reporter)

    reporter.print_console()

    os.makedirs("reports", exist_ok=True)
    reporter.to_json("reports/audit_report.json")
    reporter.to_html("reports/audit_report.html")

    print("[*] Аудит завершён.")


if __name__ == "__main__":
    main()