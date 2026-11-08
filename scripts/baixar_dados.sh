#!/usr/bin/env bash
# Baixa o CSV-03-11.zip (dia de teste do CIC-DDoS2019) e extrai os arquivos usados.
# Pasta de dados: $DDOS_BASE ou ~/ddos-dados (fora do repositório).
set -euo pipefail

BASE="${DDOS_BASE:-$HOME/ddos-dados}"
mkdir -p "$BASE/teste"
cd "$BASE"

if [ ! -f CSV-03-11.zip ]; then
  wget -c -O CSV-03-11.zip \
    "https://cicresearch.ca//CICDataset/CICDDoS2019/download.php?file=CSVs%2FCSV-03-11.zip"
fi

unzip -j -o CSV-03-11.zip \
  "03-11/LDAP.csv" "03-11/MSSQL.csv" "03-11/NetBIOS.csv" \
  "03-11/Portmap.csv" "03-11/UDPLag.csv" -d teste

ls -lh teste
