# HTTP Security Headers Analyzer (sechead-checker)

Ferramenta robusta e extensível para análise automática de cabeçalhos de segurança HTTP e detecção de headers sensíveis em websites.  

---

## Índice

- [Instalação](#instalação)
- [Como Utilizar](#como-utilizar)
  - [1. Scan individual (CLI)](#1-scan-individual-cli)
  - [2. Scan em lote (planilha-txt-csv)](#2-scan-em-lote-planilha-txt-csv)
  - [3. Visualização de resultados salvos](#3-visualização-de-resultados-salvos)
- [Features Explicadas](#features-explicadas)
- [Exportação de resultados](#exportação-de-resultados)
- [Personalização do JSON de configuração](#personalização-do-json-de-configuração)
- [Dicas e Limitações](#dicas-e-limitações)
- [Requisitos](#requisitos)
- [Licença](#licença)

---

# Instalação

**Clone este repositório:**
   ```bash
   git clone https://github.com/ppay-alvdavid/sechead-checker
   ```

### Instale as dependências:
pip install -r requirements.txt

---
# Como Utilizar
O script principal é o main.py, que oferece três modos de operação:

### 1. Scan individual (CLI)
**Analise um único site pelo terminal.** 
```bash
python main.py;
```
1.1 Escolha a opção 1.

1.2 Digite o domínio ou URL desejado (ex: exemplo.com ou https://exemplo.com).

1.3 O script faz a análise dos headers e mostra o resultado colorido no terminal.

### 2. Scan em lote (planilha-txt-csv)
**Permite processar múltiplos domínios de uma só vez a partir de um arquivo de entrada.** Prepare uma planilha .xlsx, .xls, .csv ou .txt com cada host/domínio na primeira coluna.

```bash
python main.py
```

2.1 Escolha a opção 2.

2.2 Selecione o arquivo.

2.3 O resultado será exibido em lote.

### 3. Visualização de resultados salvos
**Visualize relatórios que já foram gerados em outro momento.**

```bash
python main.py
```

3.1 Escolha a opção 3.

3.2 Selecione um arquivo .json previamente salvo.

# Features Explicadas

- Validação automática de HTTPS: Apenas domínios que respondem por HTTPS são analisados, outros são ignorados com aviso.

- Análise por CWE: Cada header é relacionado a uma CWE (Common Weakness Enumeration), facilitando diagnóstico técnico.

  - Saída colorida (colorama):

  - Verde: headers adequados

  - Vermelho: headers ausentes

  - Amarelo: headers em estado de atenção (ex: X-XSS-Protection ativo)

  - Magenta: headers sensíveis expostos

- Processamento em lote: Analise múltiplos domínios rapidamente a partir de arquivos de entrada.

- Exportação de resultados: Relatórios podem ser exportados em JSON para documentação, compliance ou auditoria futura.

- Importação e visualização de relatórios: Importe e exiba arquivos de resultados antigos.

- Interface gráfica para seleção de arquivos: Não é necessário digitar caminhos manualmente graças à integração com o tkinter.

- Exportação de resultados: Ao fim de cada análise (individual ou em lote), você pode salvar o relatório completo no formato JSON. Este arquivo pode ser compartilhado, versionado ou aberto novamente na ferramenta para análise posterior.

# Requisitos
- Python 3.7 ou superior

- Internet durante as análises

- Dependências listadas em requirements.txt:
  - pandas
  - requests
  - colorama
  - tk
  - openpyxl

# Licença
Este projeto está licenciado sob a The Unlicense, domínio público.
Sinta-se livre para usar, modificar e distribuir sem restrições.
