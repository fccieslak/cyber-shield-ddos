#!/usr/bin/env python3
"""Carrega CSVs de fluxos num banco DuckDB, guiado por um arquivo de configuração.

Uso:  python painel/ingestao.py painel/configs/cic-ddos2019.json
Cria ou completa o banco (padrão: ~/ddos-dados/fluxos.duckdb) com as tabelas
fluxos (um fluxo por linha) e resumo (medidas de cada tipo de tráfego).
Arquivos já carregados são pulados, então dá para rodar de novo sem duplicar.
"""
import glob
import json
import os
import shutil
import sys
import time

import duckdb

# nome no banco -> tipo SQL (os nomes no CSV vêm do arquivo de configuração)
COLUNAS = {
    "tipo": "VARCHAR", "ts": "TIMESTAMP", "sip": "VARCHAR", "sport": "INTEGER",
    "dip": "VARCHAR", "dport": "INTEGER", "proto": "SMALLINT", "duracao": "DOUBLE",
    "pkts_fwd": "DOUBLE", "pkts_bwd": "DOUBLE", "bytes_fwd": "DOUBLE",
    "bytes_bwd": "DOUBLE", "bytes_s": "DOUBLE", "pkts_s": "DOUBLE",
}


def expressao(nome, coluna_csv, prefixo):
    c = f'"{coluna_csv}"'
    if nome == "tipo":
        return f"regexp_replace(TRIM(CAST({c} AS VARCHAR)), '^{prefixo}', '')"
    if nome == "ts":
        return f"TRY_CAST(CAST({c} AS VARCHAR) AS TIMESTAMP)"
    if nome in ("sip", "dip"):
        return f"TRIM(CAST({c} AS VARCHAR))"
    tipo = COLUNAS[nome]
    if tipo == "DOUBLE":
        return f"CASE WHEN isfinite(TRY_CAST({c} AS DOUBLE)) THEN TRY_CAST({c} AS DOUBLE) END"
    return f"TRY_CAST({c} AS {tipo})"


def carregar(con, cfg):
    prefixo = cfg.get("remover_prefixo_rotulo", "")
    for dia, pasta in cfg["pastas"].items():
        for arq in sorted(glob.glob(os.path.join(os.path.expanduser(pasta), "*.csv"))):
            nome = os.path.basename(arq)
            ja = con.execute("SELECT count(*) FROM fluxos WHERE dataset=? AND dia=? AND arquivo=?",
                             [cfg["nome"], dia, nome]).fetchone()[0]
            if ja:
                print(f"[{dia}] {nome}: já carregado ({ja} fluxos), pulando")
                continue
            leitura = f"read_csv_auto('{arq}', header=true, ignore_errors=true)"
            cols = {r[0].strip(): r[0] for r in con.execute(f"DESCRIBE SELECT * FROM {leitura}").fetchall()}
            falt = [v for v in cfg["colunas"].values() if v not in cols]
            if falt:
                print(f"[{dia}] {nome}: colunas ausentes {falt}, arquivo ignorado")
                continue
            partes = [f"'{cfg['nome']}'", f"'{dia}'", f"'{nome}'"]
            partes += [expressao(n, cols[cfg["colunas"][n]], prefixo) for n in COLUNAS]
            t0 = time.time()
            print(f"[{dia}] {nome}: carregando ...", flush=True)
            con.execute(f"INSERT INTO fluxos SELECT {', '.join(partes)} FROM {leitura}")
            n = con.execute("SELECT count(*) FROM fluxos WHERE dataset=? AND dia=? AND arquivo=?",
                            [cfg["nome"], dia, nome]).fetchone()[0]
            print(f"[{dia}] {nome}: {n} fluxos em {time.time() - t0:.0f} s", flush=True)


def resumir(con):
    print("calculando o resumo de cada tipo de tráfego ...", flush=True)
    con.execute("""
        CREATE OR REPLACE TABLE resumo AS
        WITH base AS (
            SELECT dataset, dia, tipo, count(*) AS fluxos,
                   count(DISTINCT sip) AS ips_origem, count(DISTINCT dip) AS ips_destino,
                   count(DISTINCT sport) AS portas_origem, count(DISTINCT dport) AS portas_destino,
                   entropy(sport) AS ent_porta_origem, entropy(dport) AS ent_porta_destino,
                   entropy(sip) AS ent_ip_origem, entropy(dip) AS ent_ip_destino,
                   min(ts) AS inicio, max(ts) AS fim
            FROM fluxos GROUP BY ALL),
        po AS (SELECT dataset, dia, tipo, sport AS porta_origem_top, count(*) AS n FROM fluxos
               GROUP BY dataset, dia, tipo, sport QUALIFY row_number() OVER (PARTITION BY dataset, dia, tipo ORDER BY n DESC) = 1),
        pd AS (SELECT dataset, dia, tipo, dport AS porta_destino_top, count(*) AS n FROM fluxos
               GROUP BY dataset, dia, tipo, dport QUALIFY row_number() OVER (PARTITION BY dataset, dia, tipo ORDER BY n DESC) = 1)
        SELECT b.*, po.porta_origem_top, po.n / b.fluxos AS frac_porta_origem_top,
               pd.porta_destino_top, pd.n / b.fluxos AS frac_porta_destino_top
        FROM base b JOIN po USING (dataset, dia, tipo) JOIN pd USING (dataset, dia, tipo)
        ORDER BY dataset, dia, tipo
    """)


def main():
    if len(sys.argv) < 2:
        sys.exit("Uso: python painel/ingestao.py painel/configs/cic-ddos2019.json")
    cfg = json.load(open(sys.argv[1], encoding="utf-8"))
    banco = os.path.expanduser(cfg.get("banco", "~/ddos-dados/fluxos.duckdb"))
    pasta_banco = os.path.dirname(banco)
    livre = shutil.disk_usage(pasta_banco).free / 1e9
    if livre < 5:
        sys.exit(f"Só {livre:.1f} GB livres em {pasta_banco}. Libere espaço antes (mínimo 5 GB).")
    tmp = os.path.join(pasta_banco, "tmp_duckdb")
    con = duckdb.connect(banco)
    con.execute(f"SET memory_limit='1GB'; SET threads=2; SET preserve_insertion_order=false; SET temp_directory='{tmp}'")
    defs = ", ".join(f"{n} {t}" for n, t in COLUNAS.items())
    con.execute(f"CREATE TABLE IF NOT EXISTS fluxos (dataset VARCHAR, dia VARCHAR, arquivo VARCHAR, {defs})")
    carregar(con, cfg)
    resumir(con)
    print(con.sql("SELECT dataset, dia, tipo, fluxos, ips_origem, portas_origem, portas_destino, "
                  "round(frac_porta_origem_top, 3) AS frac_po, round(frac_porta_destino_top, 3) AS frac_pd "
                  "FROM resumo"))
    con.close()
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"banco: {banco} ({os.path.getsize(banco) / 1e9:.2f} GB)")


if __name__ == "__main__":
    main()
