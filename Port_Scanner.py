import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


def scan_port(target: str, port: int, timeout: float = 1.0) -> int:
    """Tenta estabelecer uma ligação TCP com um porto específico.

    Returns:
        int: O número do porto se estiver aberto, None caso contrário.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            return port
    return None


def run_scanner(target: str, ports: range, max_threads: int = 100):
    """Gere o pool de threads para acelerar o processo de scanning."""
    print(f"\n[+] A iniciar scan em: {target}")
    print(f"[+] Hora de início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    open_ports = []

    try:
        # Resolução de DNS
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Erro: Não foi possível resolver o hostname.", file=sys.stderr)
        return

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Mapeamento do scan de forma assíncrona/concorrente
        futures = [
            executor.submit(scan_port, target_ip, port) for port in ports
        ]

        for future in futures:
            result = future.result()
            if result:
                print(f"[ MATCH ] Porto {result}: ABERTO")
                open_ports.append(result)

    print("-" * 50)
    print(f"[+] Scan concluído. Total de portos abertos: {len(open_ports)}")


def main():
    target = input("Introduza o IP ou Hostname alvo (ex: localhost): ") or "127.0.0.1"
    # Portos mais comuns para um scan rápido
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080
    ]
    
    try:
        run_scanner(target, common_ports)
    except KeyboardInterrupt:
        print("\n[-] Scan interrompido pelo utilizador.", file=sys.stderr)
    finally:
        # Mantém a janela aberta até pressionar Enter
        input("\nPressione Enter para sair...")


if __name__ == "__main__":
    main()
