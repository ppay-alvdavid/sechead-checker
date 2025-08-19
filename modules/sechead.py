import requests

def analyze_headers(headers, config):
    result_json = {}
    cwe_results = {}

    for header_info in config['owasp_security_headers']:
        header_name = header_info['name']
        cwe = header_info['cwe']

        if cwe not in cwe_results:
            cwe_results[cwe] = {
                "security_headers": [],
                "sensitive_headers": [],
                "missing_security_headers": []
            }

        if header_name.lower() == 'x-xss-protection':
            value = headers.get(header_name, None)
            if value is None or str(value).strip().lower() in ["0", "false", "off", "disable"]:
                cwe_results[cwe]["security_headers"].append(
                    {
                        "header": header_name,
                        "valor": "Desativado",
                        "cor": "verde",
                        "destaque_status": "Desativado"
                    }
                )
            else:
                cwe_results[cwe]["security_headers"].append(
                    {
                        "header": header_name,
                        "valor": value,
                        "cor": "amarelo",
                        "destaque_status": "Ativar X-XSS-Protection não é recomendado"
                    }
                )
        else:
            value = headers.get(header_name, None)
            if value is not None:
                cwe_results[cwe]["security_headers"].append(
                    {
                        "header": header_name,
                        "valor": "",
                        "cor": "verde"
                    }
                )
            else:
                cwe_results[cwe]["missing_security_headers"].append(header_name)

    for sh in config['sensitive_headers']:
        header_name = sh['name']
        cwe = sh['cwe']
        if cwe not in cwe_results:
            cwe_results[cwe] = {
                "security_headers": [],
                "sensitive_headers": [],
                "missing_security_headers": []
            }
        value = headers.get(header_name, None)
        if value is not None:
            cwe_results[cwe]["sensitive_headers"].append(
                {
                    "header": header_name,
                    "valor": value
                }
            )

    result_json['cwe'] = cwe_results
    result_json['headers'] = {k: v for k, v in headers.items()}
    return result_json

def analyze_host(url, config):
    try:
        response = requests.get(url, timeout=15)
        headers = response.headers
        analysis = analyze_headers(headers, config)
        analysis['status_code'] = response.status_code
        analysis['host'] = url
        return analysis
    except Exception as e:
        return {
            "host": url,
            "erro": str(e)
        }