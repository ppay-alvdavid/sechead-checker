import pandas as pd
import os
import json
import tkinter as tk
from tkinter import filedialog
from colorama import Fore, Style, init
import requests

from modules.sechead import analyze_host
from modules.exporter import export_json

init(autoreset=True)

def load_config(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config

def read_hosts_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in [".xls", ".xlsx"]:
        df = pd.read_excel(file_path)
    elif ext == ".csv":
        df = pd.read_csv(file_path)
    elif ext == ".txt":
        df = pd.read_csv(file_path, header=None)
    else:
        raise Exception("Formato de arquivo não suportado! Use .csv, .xls, .xlsx ou .txt")
    hosts = df.iloc[:,0].dropna().unique().tolist()
    return [str(h).strip() for h in hosts if str(h).strip()]

def select_input_file():
    root = tk.Tk()
    root.withdraw()
    file = filedialog.askopenfilename(title="Arquivo de hosts", 
                                      filetypes=[("Planilhas e CSV", "*.xlsx *.xls *.csv *.txt")])
    return file

def select_json_file():
    root = tk.Tk()
    root.withdraw()
    file = filedialog.askopenfilename(title="Abrir arquivo de resultados (.json)", 
                                      filetypes=[("Arquivo JSON", "*.json")])
    return file

def select_output_file(suggestion="resultado.json"):
    root = tk.Tk()
    root.withdraw()
    out = filedialog.asksaveasfilename(defaultextension=".json",
                                       title="Salvar o resultado em...",
                                       initialfile=suggestion,
                                       filetypes=[("Arquivo JSON", "*.json")])
    return out

def print_cli_result(analysis, config):
    print(f"{Fore.LIGHTCYAN_EX}--- Security Headers ---")
    for cwe, data in analysis['cwe'].items():
        desc = config['cwe_descriptions'].get(cwe, '-')
        if any([data['security_headers'], data['missing_security_headers'], data['sensitive_headers']]):
            print(f"{Fore.LIGHTCYAN_EX}\n[{cwe}] {desc}")
            for h in data['security_headers']:
                valor = h.get('valor', '')
                if h["header"].lower() == "x-xss-protection":
                    if h.get('cor') == 'verde':
                        print(f"  {Fore.GREEN}{h['header']} (Desativado, OK) {Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.YELLOW}{h['header']} (ATIVO): Ativar X-XSS-Protection não é recomendado {Style.RESET_ALL}")
                else:
                    print(f"  {Fore.GREEN}{h['header']}: {valor}{Style.RESET_ALL}")
            for h in data['missing_security_headers']:
                print(f"  {Fore.RED}{h} (faltante)")
            for h in data['sensitive_headers']:
                print(f"  {Fore.LIGHTMAGENTA_EX}{h['header']}: {h['valor']}")
    print(f"{Fore.LIGHTWHITE_EX}\nPara mais info: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html\n")

def print_simple_batch_result(results, config=None):
    for analysis in results:
        host = analysis.get("host", "[Host não identificado]")
        status_code = analysis.get("status_code", "N/A")
        print(f"\n{Fore.LIGHTCYAN_EX}HOST: {host}")
        print(f"STATUS CODE: {status_code}")

        ativos = []
        inativos = []

        for cwe_data in analysis.get("cwe", {}).values():
            for h in cwe_data.get('security_headers', []):
                valor = h.get('valor', '')
                if h['header'].lower() == "x-xss-protection":
                    if h.get('cor') == 'verde':
                        ativos.append(f"{Fore.GREEN}{h['header']} (Desativado, OK) {Style.RESET_ALL}")
                    else:
                        ativos.append(f"{Fore.YELLOW}{h['header']} (ATIVO): Ativar o X-XSS-Protection não é recomendado {Style.RESET_ALL}")
                else:
                    ativos.append(f"{Fore.GREEN}{h['header']}: {valor}{Style.RESET_ALL}")
            for h in cwe_data.get('missing_security_headers', []):
                inativos.append(f"{Fore.RED}{h}{Style.RESET_ALL}")

        if ativos:
            print(f"{Fore.LIGHTGREEN_EX}\nATIVOS:")
            for h in ativos:
                print("  " + h)
        else:
            print(f"{Fore.LIGHTGREEN_EX}ATIVOS: nenhum detectado.")

        if inativos:
            print(f"{Fore.LIGHTRED_EX}\nINATIVOS:")
            for h in inativos:
                print("  " + h)
        else:
            print(f"{Fore.LIGHTRED_EX}INATIVOS: nenhum ausente.")

        print(f"\n{Fore.LIGHTWHITE_EX}{'-'*45}")

    print(f"{Fore.LIGHTWHITE_EX}\nPara mais info: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html\n")

def importar_resultados():
    file_path = select_json_file()
    if not file_path or not os.path.exists(file_path):
        print("Arquivo não encontrado ou não selecionado.")
        return
    with open(file_path, 'r', encoding='utf-8') as f:
        results = json.load(f)
    if isinstance(results, dict):
        results = [results]
    print_simple_batch_result(results)

def limpar_terminal():
    os.system("cls" if os.name == "nt" else "clear")

def validar_url_https(url):
    url = url.strip()
    if url.lower().startswith("http://"):
        print("Este script só funciona para URLs que estão no protocolo HTTPS/SSL-TLS.")
        return None
    if url.lower().startswith("https://"):
        return url
    # Remove protocolo, se houver, e tenta https://
    dominio = url.replace("https://", "").replace("http://", "").split('/')[0]
    test_url = "https://" + dominio
    try:
        resp = requests.get(test_url, timeout=6)
        if resp.status_code == 200:
            print(f"Protocolo SSL/TLS detectado. Usando: {test_url}")
            return test_url
        else:
            print(f"Não foi possível conectar via HTTPS à URL: {test_url}")
            return None
    except Exception:
        print(f"Não foi possível conectar via HTTPS à URL: {test_url}")
        return None

def perguntar_salvar_resultado(tipo_scan, sugestao_nome, resultado):
    resposta = input("\nDeseja salvar os resultados do scan? (S/n): ").strip().lower()
    if resposta in ['', 's', 'sim']:
        file_path = select_output_file(suggestion=sugestao_nome)
        if file_path:
            export_json(resultado, file_path)
            print(f"Arquivo salvo em: {file_path}")

def main():
    limpar_terminal()
    config_path = os.path.join("config", "headers_cwe.json")
    config = load_config(config_path)
    print("Selecione a opção:\n1. Scan individual\n2. Scan múltiplos\n3. Importar resultados (.json)")
    option = input("Opção: ").strip()
    if option == "1":
        limpar_terminal()
        url_input = input("Digite o URL do site (ex: exemplo.com ou https://exemplo.com): ").strip()
        url_validada = validar_url_https(url_input)
        if not url_validada:
            print("Forneça uma URL válida no protocolo HTTPS.")
            return
        analysis = analyze_host(url_validada, config)
        print_cli_result(analysis, config)
        perguntar_salvar_resultado(
            tipo_scan="individual",
            sugestao_nome=f"resultado_{url_validada.replace('https://','').replace('http://','').replace('/','_')}.json",
            resultado=analysis
        )
    elif option == "2":
        limpar_terminal()
        input_file = select_input_file()
        if not input_file:
            print("Nenhum arquivo selecionado.")
            return
        hosts = read_hosts_file(input_file)
        results = []
        for host in hosts:
            url_validada = validar_url_https(host)
            if not url_validada:
                print(f"Endereço '{host}' ignorado (não é HTTPS ou não responde neste protocolo).")
                continue
            analysis = analyze_host(url_validada, config)
            results.append(analysis)
            print(f"Analisado: {host}")
        if not results:
            print("Nenhum host analisável via HTTPS foi encontrado.")
            return
        print_simple_batch_result(results, config)
        perguntar_salvar_resultado(
            tipo_scan="multiplo",
            sugestao_nome="resultado_lote.json",
            resultado=results
        )
    elif option == "3":
        limpar_terminal()
        importar_resultados()
    else:
        print("Opção inválida!")

if __name__ == "__main__":
    main()
