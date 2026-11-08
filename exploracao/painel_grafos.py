#!/usr/bin/env python3
"""Painel de grafos por tipo de trafego do CIC-DDoS2019 (dia de teste).

Cada fluxo dos CSVs vira uma aresta entre dois nos (IP:porta de origem e IP:porta de destino).
Cada tipo de trafego forma uma "ilha" no mapa; o BENIGN forma uma ilha por arquivo.
A linha do tempo usa os horarios medidos nos timestamps.

Passo 1 (demora; le os CSVs; precisa de duckdb e numpy do venv):
    source ~/venv-ddos/bin/activate
    cd ~/ddos-dados && python painel_grafos.py --medir

Passo 2 (so gera o HTML a partir das medidas; segundos):
    cd ~/ddos-dados && python painel_grafos.py

Verificacao (confere se o grafo corresponde a tabela dos CSVs; precisa de scipy):
    cd ~/ddos-dados && python painel_grafos.py --verificar

Entrada : <BASE>/teste/*.csv
Saidas  : <BASE>/painel_grafos.json, <BASE>/painel_grafos.html e
          <BASE>/auditoria_grafos.csv (os fluxos exatos usados em cada grafo)
"""
import csv
import glob
import json
import math
import os
import random
import sys
from collections import Counter, defaultdict

BASE = os.environ.get("DDOS_BASE", os.path.expanduser("~/ddos-dados"))
PASTA = os.path.join(BASE, "teste")
MEDIDAS = os.path.join(BASE, "painel_grafos.json")
SAIDA = os.path.join(BASE, "painel_grafos.html")
AUDITORIA = os.path.join(BASE, "auditoria_grafos.csv")
N_FLUXOS = 200            # fluxos usados por ilha para construir o grafo
SEMENTE_AMOSTRA = 42      # muda a amostra (mesmo valor = mesma amostra)
LARG, ALT = 900, 480      # tamanho do mapa (unidades do desenho)
LACUNA_MIN = 2            # minutos sem fluxo que ainda contam como o mesmo trecho
LONGO = 90                # trechos com mais de 90 min sao cortados no eixo

REFLEXAO = {"DNS", "NTP", "LDAP", "MSSQL", "NetBIOS", "SNMP", "SSDP", "TFTP", "Portmap", "CharGen"}
EXPLORACAO = {"Syn", "UDP", "UDPLag"}


def familia(t):
    if t == "BENIGN":
        return "norm"
    if t in REFLEXAO:
        return "refl"
    if t in EXPLORACAO:
        return "expl"
    return "out"


# --------------------------------------------------------------------------
# Passo 1: medir
# --------------------------------------------------------------------------
def criar_f(con, arq):
    """Le o CSV e cria a tabela temporaria f com as colunas usadas. Devolve False se faltar coluna."""
    leitura = f"read_csv_auto('{arq}', header=true, ignore_errors=true)"
    cols = [r[0] for r in con.sql(f"DESCRIBE SELECT * FROM {leitura}").fetchall()]
    m = {c.strip(): c for c in cols}
    precisa = ["Label", "Source IP", "Source Port", "Destination IP", "Destination Port"]
    falt = [c for c in precisa if c not in m]
    if falt:
        print(f"   colunas ausentes {falt}; arquivo ignorado")
        return False
    ts = (f'TRY_CAST(CAST("{m["Timestamp"]}" AS VARCHAR) AS TIMESTAMP)'
          if "Timestamp" in m else "CAST(NULL AS TIMESTAMP)")
    fid = f'CAST("{m["Flow ID"]}" AS VARCHAR)' if "Flow ID" in m else "CAST(NULL AS VARCHAR)"
    con.sql(f"""
        CREATE OR REPLACE TEMP TABLE f AS
        SELECT regexp_replace(TRIM(CAST("{m['Label']}" AS VARCHAR)), '^DrDoS_', '') AS tipo,
               {fid} AS fid,
               {ts} AS ts,
               CAST("{m['Source IP']}" AS VARCHAR) AS sip,
               TRY_CAST("{m['Source Port']}" AS BIGINT) AS sport,
               CAST("{m['Destination IP']}" AS VARCHAR) AS dip,
               TRY_CAST("{m['Destination Port']}" AS BIGINT) AS dport
        FROM {leitura}
    """)
    return True


def ler_csvs():
    import duckdb

    arquivos = sorted(glob.glob(os.path.join(PASTA, "*.csv")))
    if not arquivos:
        sys.exit(f"Nenhum CSV em {PASTA}")
    con = duckdb.connect()
    con.sql("SET memory_limit='1GB'; SET threads=2;")
    minutos = defaultdict(set)
    minutos_ilha = defaultdict(set)
    arestas = defaultdict(list)
    totais = Counter()
    for arq in arquivos:
        nome = os.path.splitext(os.path.basename(arq))[0]
        print(f"lendo {os.path.basename(arq)} ...", flush=True)
        if not criar_f(con, arq):
            continue
        nulos = con.sql("SELECT COUNT(*) FROM f WHERE sip IS NULL OR dip IS NULL "
                        "OR sport IS NULL OR dport IS NULL").fetchall()[0][0]
        if nulos:
            print(f"   {nulos} fluxos sem IP ou porta foram desconsiderados")
        for tipo, mi in con.sql("""
            SELECT tipo, CAST(epoch(date_trunc('minute', ts)) / 60 AS BIGINT)
            FROM f WHERE ts IS NOT NULL GROUP BY 1, 2
        """).fetchall():
            minutos[tipo].add(int(mi))
            minutos_ilha[tipo if tipo != "BENIGN" else f"BENIGN::{nome}"].add(int(mi))
        for tipo, c in con.sql("SELECT tipo, COUNT(*) FROM f GROUP BY 1").fetchall():
            totais[tipo if tipo != "BENIGN" else f"BENIGN::{nome}"] += int(c)
        for tipo in [r[0] for r in con.sql("SELECT DISTINCT tipo FROM f").fetchall()]:
            q = tipo.replace("'", "''")
            # amostra reproduzivel: os N fluxos com menor hash do conteudo (mesma amostra a cada execucao)
            linhas = con.sql(f"""
                SELECT fid, CAST(ts AS VARCHAR), sip, sport, dip, dport
                FROM f
                WHERE tipo = '{q}' AND sip IS NOT NULL AND dip IS NOT NULL
                  AND sport IS NOT NULL AND dport IS NOT NULL
                ORDER BY hash(COALESCE(fid, ''), CAST(ts AS VARCHAR), sip, sport, dip, dport, {SEMENTE_AMOSTRA})
                LIMIT {N_FLUXOS}
            """).fetchall()
            ilha = tipo if tipo != "BENIGN" else f"BENIGN::{nome}"
            arestas[ilha].extend([(nome, tipo) + tuple(l) for l in linhas])
    return minutos, arestas, totais, minutos_ilha


def layout_fr(np, n, edges, rng, iteracoes=150):
    """Fruchterman-Reingold simples, vetorizado. Devolve posicoes normalizadas (raio maximo 1)."""
    if n == 1:
        return np.zeros((1, 2))
    pos = rng.random((n, 2))
    ea = np.array([e[0] for e in edges], dtype=int)
    eb = np.array([e[1] for e in edges], dtype=int)
    k = 1.0 / math.sqrt(n)
    temp = 0.15
    for _ in range(iteracoes):
        d = pos[:, None, :] - pos[None, :, :]
        dist = np.sqrt((d ** 2).sum(2)) + 1e-6
        disp = ((d / dist[:, :, None]) * ((k * k) / dist)[:, :, None]).sum(1)
        if len(ea):
            dd = pos[ea] - pos[eb]
            dl = np.sqrt((dd ** 2).sum(1)) + 1e-6
            f = ((dl * dl) / k)[:, None] * dd / dl[:, None]
            np.add.at(disp, ea, -f)
            np.add.at(disp, eb, f)
        disp -= (pos - pos.mean(0)) * 0.3
        ln = np.sqrt((disp ** 2).sum(1)) + 1e-9
        pos += disp / ln[:, None] * np.minimum(ln, temp)[:, None]
        temp *= 0.96
    pos -= pos.mean(0)
    rmax = np.sqrt((pos ** 2).sum(1)).max()
    return pos / (rmax if rmax > 0 else 1)


def layout_radial(np, n, edges, rng):
    """Layout radial a partir do no mais ligado: filhos em volta do pai, com as linhas visiveis."""
    rot = rng.random() * 2 * math.pi
    if n == 2:
        return np.array([[-math.cos(rot), -math.sin(rot)], [math.cos(rot), math.sin(rot)]])
    adj = [[] for _ in range(n)]
    for a, b in edges:
        adj[a].append(b)
        adj[b].append(a)
    raiz = max(range(n), key=lambda x: len(adj[x]))
    nivel, pai, ordem = [-1] * n, [-1] * n, [raiz]
    nivel[raiz] = 0
    for u in ordem:
        for v in adj[u]:
            if nivel[v] < 0:
                nivel[v], pai[v] = nivel[u] + 1, u
                ordem.append(v)
    filhos = [[] for _ in range(n)]
    for v in ordem[1:]:
        filhos[pai[v]].append(v)
    folhas = [1] * n
    for v in reversed(ordem):
        if filhos[v]:
            folhas[v] = sum(folhas[c] for c in filhos[v])
    lo, hi = [0.0] * n, [0.0] * n
    hi[raiz] = 2 * math.pi
    for u in ordem:
        a0, tot = lo[u], sum(folhas[c] for c in filhos[u]) or 1
        for c in filhos[u]:
            w = (hi[u] - lo[u]) * folhas[c] / tot
            lo[c], hi[c] = a0, a0 + w
            a0 += w
    pos = np.zeros((n, 2))
    for v in ordem:
        if v == raiz:
            continue
        ang = (lo[v] + hi[v]) / 2 + rot
        r = nivel[v] * (1 + 0.22 * rng.random())
        pos[v] = [r * math.cos(ang), r * math.sin(ang)]
    rmax = np.sqrt((pos ** 2).sum(1)).max()
    return pos / (rmax if rmax > 0 else 1)


def componentes(n, edges):
    pai = list(range(n))

    def raiz(x):
        while pai[x] != x:
            pai[x] = pai[pai[x]]
            x = pai[x]
        return x
    for a, b in edges:
        pai[raiz(a)] = raiz(b)
    grupos = defaultdict(list)
    for i in range(n):
        grupos[raiz(i)].append(i)
    return list(grupos.values())


def empacotar(np, rs, rng, iteracoes=35):
    """Posiciona circulos de raios rs dentro do disco unitario, sem sobreposicao."""
    m = len(rs)
    ang = rng.uniform(0, 2 * math.pi, m)
    raio = np.sqrt(rng.uniform(0, 1, m)) * np.maximum(1 - rs, 0.05)
    c = np.stack([raio * np.cos(ang), raio * np.sin(ang)], axis=1)
    c[0] = 0
    for _ in range(iteracoes):
        d = c[:, None, :] - c[None, :, :]
        dist = np.sqrt((d ** 2).sum(2)) + 1e-9
        sobra = np.maximum(rs[:, None] + rs[None, :] - dist, 0)
        np.fill_diagonal(sobra, 0)
        c += ((d / dist[:, :, None]) * (sobra[:, :, None] / 2)).sum(1)
        r = np.sqrt((c ** 2).sum(1))
        lim = np.maximum(1 - rs, 0.01)
        c *= np.minimum(1, lim / (r + 1e-9))[:, None]
    return c


def construir_ilhas(np, arestas, totais):
    rnd = random.Random(42)
    rng = np.random.default_rng(42)
    ilhas = []
    for nome in sorted(arestas, key=lambda x: (x.startswith("BENIGN"), x)):
        linhas = arestas[nome]
        rnd.shuffle(linhas)
        linhas = linhas[:N_FLUXOS]
        ids, uniq = {}, set()
        for _arq, _lab, _fid, _ts, sip, sport, dip, dport in linhas:
            par = []
            for ip, p in ((sip, sport), (dip, dport)):
                k = f"{ip}:{p}"
                if k not in ids:
                    ids[k] = len(ids)
                par.append(ids[k])
            if par[0] != par[1]:
                uniq.add((min(par), max(par)))
        if not uniq:
            continue
        nomes_orig = {v: k for k, v in ids.items()}
        usados = sorted({x for e in uniq for x in e})
        novo_id = {v: i for i, v in enumerate(usados)}
        n = len(usados)
        edges = sorted((novo_id[a], novo_id[b]) for a, b in uniq)
        nomes = [nomes_orig[v] for v in usados]
        deg = [0] * n
        for a, b in edges:
            deg[a] += 1
            deg[b] += 1
        comps = sorted(componentes(n, edges), key=len, reverse=True)
        rs = np.array([0.03 + 0.42 * math.sqrt(len(c) / n) for c in comps])
        centros = empacotar(np, rs, rng)
        pos = np.zeros((n, 2))
        csize = [0] * n
        for ci, comp in enumerate(comps):
            loc = {g: i for i, g in enumerate(comp)}
            ec = [(loc[a], loc[b]) for a, b in edges if a in loc]
            pc = layout_radial(np, len(comp), ec, rng)
            for g, i in loc.items():
                pos[g] = centros[ci] + pc[i] * rs[ci]
                csize[g] = len(comp)
        tipo = nome.split("::")[0]
        ilhas.append({"id": tipo, "arquivo": nome, "linhas": linhas, "total": totais.get(nome, 0),
                      "fam": familia(tipo), "n": n, "pos": pos,
                      "edges": edges, "deg": deg, "csize": csize, "nomes": nomes,
                      "ncomp": len(comps), "maior": len(comps[0])})
    return ilhas


def diagnostico(ilhas):
    print()
    print(f"{'estrutura':<20}{'no CSV':>10}{'usados':>8}{'nós':>6}{'ligações':>10}{'grupos':>8}{'maior':>7}  nó mais ligado")
    for i in ilhas:
        k = max(range(i["n"]), key=lambda x: i["deg"][x])
        print(f"{i['arquivo']:<20}{i['total']:>10}{len(i['linhas']):>8}{i['n']:>6}{len(i['edges']):>10}"
              f"{i['ncomp']:>8}{i['maior']:>7}  {i['nomes'][k]} ({i['deg'][k]} ligações)")
    print()


def posicionar(np, ilhas):
    mx = max(i["n"] for i in ilhas)
    for i in ilhas:
        f = 0.65 if i["id"] == "BENIGN" else 1.0
        i["r0"] = f * (28 + 92 * math.sqrt(i["n"] / mx))
    rnd = random.Random(7)
    escala = 1.0
    for _ in range(14):
        for i in ilhas:
            i["R"] = i["r0"] * escala
            i["cx"] = rnd.uniform(i["R"] + 6, LARG - i["R"] - 6)
            i["cy"] = rnd.uniform(i["R"] + 6, ALT - i["R"] - 6)
        for _it in range(600):
            for a in range(len(ilhas)):
                for b in range(a + 1, len(ilhas)):
                    A, B = ilhas[a], ilhas[b]
                    dx, dy = B["cx"] - A["cx"], B["cy"] - A["cy"]
                    d = math.hypot(dx, dy) or 0.01
                    m = A["R"] + B["R"] + 12
                    if d < m:
                        p = (m - d) / 2
                        ux, uy = dx / d, dy / d
                        A["cx"] -= ux * p; A["cy"] -= uy * p
                        B["cx"] += ux * p; B["cy"] += uy * p
            for i in ilhas:
                i["cx"] = min(max(i["cx"], i["R"] + 6), LARG - i["R"] - 6)
                i["cy"] = min(max(i["cy"], i["R"] + 6), ALT - i["R"] - 6)
        ok = all(math.hypot(ilhas[b]["cx"] - ilhas[a]["cx"], ilhas[b]["cy"] - ilhas[a]["cy"])
                 >= ilhas[a]["R"] + ilhas[b]["R"] + 6
                 for a in range(len(ilhas)) for b in range(a + 1, len(ilhas)))
        if ok:
            break
        escala *= 0.9


def segmentos(ms):
    ms = sorted(ms)
    segs = []
    for m in ms:
        if segs and m - segs[-1][1] <= LACUNA_MIN + 1:
            segs[-1][1] = m + 1
        else:
            segs.append([m, m + 1])
    return segs


def tempo(minutos):
    seg = {t: segmentos(v) for t, v in minutos.items() if v}
    ataque = {t: s for t, s in seg.items() if t != "BENIGN"}
    if not seg:
        return None
    base = ataque or seg
    curtos = [s for lst in base.values() for s in lst if s[1] - s[0] < LONGO]
    ini = min(s[0] for lst in base.values() for s in lst) - 8
    longos = [s for lst in base.values() for s in lst if s[1] - s[0] >= LONGO]
    ate = [s[1] for s in curtos] + [s[0] + 15 for s in longos]
    fim = (max(ate) if ate else max(s[1] for lst in base.values() for s in lst)) + 8
    out, cortado = {}, {}
    for t, lst in seg.items():
        cortes = []
        for a, b in lst:
            if b < ini or a > fim:
                continue
            if b > fim:
                cortado[t] = True
            cortes.append([max(a, ini), min(b, fim)])
        if cortes:
            out[t] = cortes
    return {"t0": ini, "t1": fim, "seg": out, "cortado": cortado}


def passo_medir():
    import numpy as np

    minutos, arestas, totais, minutos_ilha = ler_csvs()
    ilhas = construir_ilhas(np, arestas, totais)
    if not ilhas:
        sys.exit("Nenhum grafo construido. Confira os CSVs.")
    posicionar(np, ilhas)
    diagnostico(ilhas)
    with open(AUDITORIA, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["chave", "arquivo", "label", "flow_id", "timestamp", "sip", "sport", "dip", "dport"])
        for i in ilhas:
            for arq, lab, fid, ts, sip, sport, dip, dport in i["linhas"]:
                w.writerow([i["arquivo"], arq, lab, fid or "", ts or "", sip, sport, dip, dport])
    saida = {"larg": LARG, "alt": ALT, "ilhas": [], "tempo": tempo(minutos)}
    for i in ilhas:
        nos = [[round(i["cx"] + float(x) * i["R"], 1), round(i["cy"] + float(y) * i["R"], 1), i["deg"][k], i["csize"][k]]
               for k, (x, y) in enumerate(i["pos"])]
        h = max(range(i["n"]), key=lambda x: i["deg"][x])
        info = {"total": i["total"], "usados": len(i["linhas"]), "nos": i["n"], "ligacoes": len(i["edges"]),
                "grupos": i["ncomp"], "maior": i["maior"], "hub": i["nomes"][h], "hub_grau": i["deg"][h]}
        saida["ilhas"].append({"chave": i["arquivo"], "id": i["id"], "fam": i["fam"], "cx": round(i["cx"], 1),
                               "cy": round(i["cy"], 1), "r": round(i["R"], 1), "info": info,
                               "horario": segmentos(minutos_ilha.get(i["arquivo"], [])),
                               "nos": nos, "arestas": [list(e) for e in i["edges"]]})
    with open(MEDIDAS, "w", encoding="utf-8") as f:
        json.dump(saida, f, ensure_ascii=False, separators=(",", ":"))
    print(f"{len(saida['ilhas'])} estruturas; gerado: {MEDIDAS}")
    print(f"auditoria: {AUDITORIA} (os fluxos exatos usados em cada grafo)")


def passo_verificar():
    import duckdb
    import numpy as np
    from scipy.sparse import coo_matrix
    from scipy.sparse.csgraph import connected_components

    if not (os.path.exists(AUDITORIA) and os.path.exists(MEDIDAS)):
        sys.exit("Rode antes: python painel_grafos.py --medir")
    with open(AUDITORIA, newline="", encoding="utf-8") as f:
        linhas = list(csv.DictReader(f))
    with open(MEDIDAS, encoding="utf-8") as f:
        dados = json.load(f)
    ilha_json = {i["chave"]: i for i in dados["ilhas"]}
    por_chave = defaultdict(list)
    por_arq = defaultdict(list)
    for r in linhas:
        por_chave[r["chave"]].append(r)
        por_arq[r["arquivo"]].append(r)

    print("A) cada fluxo auditado existe no CSV original, com o mesmo rotulo e os mesmos IPs e portas")
    con = duckdb.connect()
    con.sql("SET memory_limit='1GB'; SET threads=2;")
    achados = Counter()
    for nome, rs in por_arq.items():
        print(f"   conferindo {nome}.csv ...", flush=True)
        if not criar_f(con, os.path.join(PASTA, nome + ".csv")):
            continue
        con.sql("CREATE OR REPLACE TEMP TABLE a (aid BIGINT, chave VARCHAR, label VARCHAR, fid VARCHAR, "
                "ts VARCHAR, sip VARCHAR, sport BIGINT, dip VARCHAR, dport BIGINT)")
        con.executemany("INSERT INTO a VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [(k, r["chave"], r["label"], r["flow_id"] or None, r["timestamp"] or None,
                          r["sip"], int(r["sport"]), r["dip"], int(r["dport"])) for k, r in enumerate(rs)])
        for chave, c in con.sql("""
            SELECT a.chave, COUNT(DISTINCT a.aid)
            FROM a JOIN (SELECT fid, CAST(ts AS VARCHAR) AS ts, sip, sport, dip, dport, tipo FROM f) o
              ON a.fid IS NOT DISTINCT FROM o.fid AND a.ts IS NOT DISTINCT FROM o.ts
             AND a.sip = o.sip AND a.sport = o.sport AND a.dip = o.dip AND a.dport = o.dport
             AND a.label = o.tipo
            GROUP BY 1
        """).fetchall():
            achados[chave] += int(c)

    print()
    print("B) o grafo desenhado corresponde a lista de fluxos auditada (reconstrucao independente)")
    print(f"{'estrutura':<20}{'fluxos':>8}{'achados no CSV':>16}{'nós':>6}{'ligações':>10}{'graus':>8}{'grupos':>8}")
    tudo_ok = True
    for chave in sorted(por_chave, key=lambda x: (x.startswith("BENIGN"), x)):
        rs = por_chave[chave]
        ids, uniq = {}, set()
        for r in rs:
            par = []
            for ip, p in ((r["sip"], r["sport"]), (r["dip"], r["dport"])):
                k = f"{ip}:{p}"
                ids.setdefault(k, len(ids))
                par.append(ids[k])
            if par[0] != par[1]:
                uniq.add((min(par), max(par)))
        usados = sorted({x for e in uniq for x in e})
        idx = {v: i for i, v in enumerate(usados)}
        n = len(usados)
        ed = [(idx[a], idx[b]) for a, b in uniq]
        deg = np.zeros(n, dtype=int)
        for a, b in ed:
            deg[a] += 1
            deg[b] += 1
        m = coo_matrix((np.ones(len(ed)), ([e[0] for e in ed], [e[1] for e in ed])), shape=(n, n))
        _, lab = connected_components(m, directed=False)
        comp_r = sorted(Counter(np.bincount(lab).tolist()).items())
        j = ilha_json.get(chave)
        if j is None:
            print(f"{chave:<20} ausente no JSON")
            tudo_ok = False
            continue
        cont = Counter(no[3] for no in j["nos"])
        comp_j = sorted((tam, c // tam) for tam, c in cont.items())
        ok_a = achados[chave] == len(rs)
        ok_n = n == len(j["nos"])
        ok_e = len(ed) == len(j["arestas"])
        ok_d = sorted(deg.tolist()) == sorted(no[2] for no in j["nos"])
        ok_c = comp_r == comp_j
        tudo_ok = tudo_ok and ok_a and ok_n and ok_e and ok_d and ok_c
        f = lambda ok: "ok" if ok else "FALHA"
        print(f"{chave:<20}{len(rs):>8}{(str(achados[chave]) + '/' + str(len(rs)) + ' ' + f(ok_a)):>16}"
              f"{f(ok_n):>6}{f(ok_e):>10}{f(ok_d):>8}{f(ok_c):>8}")
    print()
    print("TUDO CONFERE" if tudo_ok else "HA FALHAS: nao use este painel ate resolver")


# --------------------------------------------------------------------------
# Passo 2: HTML
# --------------------------------------------------------------------------
HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Grafos de tráfego, CIC-DDoS2019</title>
<style>
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body { color: #e8ecff; font-family: "Ubuntu","Segoe UI",system-ui,sans-serif; font-size: 13px;
    background: radial-gradient(ellipse 70% 60% at 12% 8%, rgba(38,66,190,0.45) 0%, transparent 60%),
                radial-gradient(ellipse 60% 60% at 90% 95%, rgba(118,40,190,0.4) 0%, transparent 62%), #070a1f;
    background-attachment: fixed; }
  #app { height: 100%; display: grid; grid-template-columns: minmax(0,1fr) 310px; gap: 12px; padding: 14px; position: relative; }
  #esq { display: grid; grid-template-rows: minmax(0,1fr) auto; gap: 12px; min-height: 0; min-width: 0; }
  .box { border: 1px solid rgba(140,160,255,0.18); border-radius: 12px; background: rgba(10,14,40,0.6); min-height: 0; overflow: hidden; }
  #map { width: 100%; height: 100%; display: block; }
  #tl { padding: 6px 8px 2px; }
  #tl svg { display: block; width: 100%; }
  #lado { padding: 14px 16px; overflow-y: auto; }
  .g { transition: opacity .15s; }
  #tip { position: absolute; display: none; pointer-events: none; z-index: 5; padding: 4px 10px; border-radius: 8px;
         border: 1px solid rgba(140,160,255,0.35); background: rgba(8,12,36,0.95); font-size: 13px; font-weight: 500; white-space: nowrap; }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; flex: none; }
  .tit { display: flex; align-items: center; gap: 8px; font-size: 17px; font-weight: 500; margin: 0 0 2px; }
  .sub { color: #9aa6d6; margin: 0 0 14px; font-size: 12px; }
  dl { margin: 0; display: grid; grid-template-columns: 1fr auto; gap: 9px 12px; }
  dt { color: #9aa6d6; }
  dd { margin: 0; text-align: right; font-variant-numeric: tabular-nums; }
  dd.mono { font-family: "Ubuntu Mono", ui-monospace, monospace; }
  .barra { height: 6px; border-radius: 3px; background: rgba(140,160,255,0.14); margin-top: 14px; overflow: hidden; }
  .barra i { display: block; height: 100%; border-radius: 3px; }
  .cab { display: grid; grid-template-columns: 1fr 58px 70px; gap: 8px; color: #9aa6d6; font-size: 11px; padding: 0 0 6px; }
  .lin { display: grid; grid-template-columns: 1fr 58px 70px; gap: 8px; align-items: center; padding: 6px 0; border-top: 1px solid rgba(140,160,255,0.1); font-variant-numeric: tabular-nums; }
  .lin .n { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .lin small { color: #9aa6d6; }
  .lin .v { text-align: right; }
</style>
</head>
<body>
<div id="app">
  <div id="esq">
    <div class="box"><svg id="map" role="img" aria-label="Grafos de cada tipo de tráfego do dia de teste"></svg></div>
    <div class="box" id="tl"></div>
  </div>
  <aside class="box" id="lado"></aside>
  <div id="tip"></div>
</div>
<script id="dados" type="application/json">__DADOS__</script>
<script>
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("dados").textContent);
  var COL = { refl: "#2dd4bf", expl: "#fb7185", norm: "#94a3b8", out: "#a5b4fc" };
  var nf = new Intl.NumberFormat("pt-BR"), nfc = new Intl.NumberFormat("pt-BR", { notation: "compact", maximumFractionDigits: 1 });
  function p2(n) { return (n < 10 ? "0" : "") + n; }
  function hm(m) { var d = new Date(m * 60000); return p2(d.getUTCHours()) + "h" + p2(d.getUTCMinutes()); }
  function pct(v) { return (v * 100).toFixed(1).replace(".", ",") + "%"; }
  function cor(f) { return COL[f] || COL.out; }
  var famDe = {}; D.ilhas.forEach(function (i) { famDe[i.id] = i.fam; });
  var porChave = {}; D.ilhas.forEach(function (i) { porChave[i.chave] = i; });

  var svg = document.getElementById("map");
  svg.setAttribute("viewBox", "0 0 " + D.larg + " " + D.alt);
  var h = "";
  D.ilhas.forEach(function (il) {
    var c = cor(il.fam), o = "", e = il.arestas.length, hub = Math.max(5, 0.12 * e);
    il.arestas.forEach(function (a) {
      var p = il.nos[a[0]], q = il.nos[a[1]], pequeno = p[3] <= 3;
      o += '<line x1="' + p[0] + '" y1="' + p[1] + '" x2="' + q[0] + '" y2="' + q[1] + '" stroke="' + c + '" stroke-width="' + (pequeno ? 0.9 : 0.8) + '" opacity="' + (pequeno ? 0.5 : 0.6) + '"/>';
    });
    il.nos.forEach(function (p) {
      var big = p[2] >= hub, pequeno = p[3] <= 3;
      o += '<circle cx="' + p[0] + '" cy="' + p[1] + '" r="' + (big ? 4.6 : (pequeno ? 1.7 : 2.1)) + '" fill="' + c + '" opacity="' + (big ? 1 : (pequeno ? 0.6 : 0.9)) + '"/>';
    });
    h += '<g class="g" data-id="' + il.id + '" data-chave="' + il.chave + '" style="cursor:pointer"><circle cx="' + il.cx + '" cy="' + il.cy + '" r="' + (il.r + 8) + '" fill="transparent"/>' + o + "</g>";
  });
  svg.innerHTML = h;

  var lado = document.getElementById("lado");
  function ordemLista() {
    var o = { refl: 0, expl: 1, out: 2, norm: 3 };
    return D.ilhas.slice().sort(function (a, b) { return (o[a.fam] - o[b.fam]) || (b.info.total - a.info.total); });
  }
  function nomeBenign(il) { return il.id === "BENIGN" ? '<small>' + il.chave.split("::")[1] + ".csv</small>" : ""; }
  function lista() {
    var s = '<div class="cab"><span>Estrutura</span><span style="text-align:right">no nó central</span><span style="text-align:right">fluxos</span></div>';
    ordemLista().forEach(function (il) {
      var f = il.info.hub_grau / Math.max(il.info.ligacoes, 1);
      s += '<div class="lin"><span class="n"><span class="dot" style="background:' + cor(il.fam) + '"></span><span>' + il.id + " " + nomeBenign(il) + '</span></span><span class="v">' + pct(f) + '</span><span class="v">' + nfc.format(il.info.total) + "</span></div>";
    });
    lado.innerHTML = s;
  }
  function detalhe(il) {
    var i = il.info, f = i.hub_grau / Math.max(i.ligacoes, 1), hor = il.horario.length ? hm(il.horario[0][0]) + " a " + hm(il.horario[il.horario.length - 1][1]) : "sem dado";
    lado.innerHTML = '<p class="tit"><span class="dot" style="background:' + cor(il.fam) + '"></span>' + il.id + "</p>" +
      '<p class="sub">' + (il.id === "BENIGN" ? il.chave.split("::")[1] + ".csv" : "&nbsp;") + "</p>" +
      "<dl><dt>Fluxos no CSV</dt><dd>" + nf.format(i.total) + "</dd><dt>Usados no grafo</dt><dd>" + nf.format(i.usados) + "</dd>" +
      "<dt>Nós</dt><dd>" + nf.format(i.nos) + "</dd><dt>Ligações</dt><dd>" + nf.format(i.ligacoes) + "</dd>" +
      "<dt>Grupos</dt><dd>" + nf.format(i.grupos) + "</dd><dt>Maior grupo</dt><dd>" + nf.format(i.maior) + " nós</dd>" +
      "<dt>Nó mais ligado</dt><dd class=\"mono\">" + i.hub + "</dd><dt>Ligações dele</dt><dd>" + nf.format(i.hub_grau) + " (" + pct(f) + ")</dd>" +
      "<dt>Horário</dt><dd>" + hor + "</dd></dl>" +
      '<div class="barra"><i style="width:' + Math.min(f * 100, 100) + "%;background:" + cor(il.fam) + '"></i></div>';
  }
  lista();

  var tl = document.getElementById("tl"), tip = document.getElementById("tip"), app = document.getElementById("app");
  var T = D.tempo, geo = null;
  function ordem() { return Object.keys(T ? T.seg : {}).filter(function (t) { return t !== "BENIGN"; }); }
  function desenharTL() {
    if (!T) { tl.innerHTML = ""; return; }
    var w = tl.clientWidth - 16, X0 = 14, X1 = w - 14, span = T.t1 - T.t0;
    function x(m) { return X0 + (m - T.t0) / span * (X1 - X0); }
    var s = '<svg width="' + w + '" height="78" viewBox="0 0 ' + w + ' 78">';
    (T.seg.BENIGN || []).forEach(function (r) {
      s += '<g class="g" data-id="BENIGN"><rect x="' + x(r[0]).toFixed(1) + '" y="42" width="' + Math.max(x(r[1]) - x(r[0]), 4).toFixed(1) + '" height="10" rx="3" fill="' + COL.norm + '" opacity="0.6"/></g>';
    });
    ordem().forEach(function (t) {
      var c = cor(famDe[t]);
      T.seg[t].forEach(function (r) {
        var x1 = x(r[0]), w2 = Math.max(x(r[1]) - x1, 9);
        s += '<g class="g" data-id="' + t + '"><rect x="' + x1.toFixed(1) + '" y="8" width="' + w2.toFixed(1) + '" height="28" rx="4" fill="' + c + '" opacity="0.88"/>';
        if (T.cortado[t] && r[1] >= T.t1) { s += '<path d="M' + (X1 - 12) + ' 15 L' + (X1 - 4) + ' 22 L' + (X1 - 12) + ' 29" fill="none" stroke="#070a1f" stroke-width="1.6"/>'; }
        s += "</g>";
      });
    });
    s += '<line x1="' + X0 + '" y1="60" x2="' + X1 + '" y2="60" stroke="rgba(140,160,255,0.4)" stroke-width="0.6"/>';
    var passo = [5, 10, 15, 30, 60].filter(function (p) { return span / p <= 10; })[0] || 120;
    for (var m = Math.ceil(T.t0 / passo) * passo; m <= T.t1; m += passo) {
      s += '<line x1="' + x(m) + '" y1="60" x2="' + x(m) + '" y2="64" stroke="rgba(140,160,255,0.4)" stroke-width="0.6"/><text x="' + x(m) + '" y="76" text-anchor="middle" font-size="12" fill="#9aa6d6">' + hm(m) + "</text>";
    }
    s += '<line id="cur" x1="0" y1="4" x2="0" y2="60" stroke="#e8ecff" stroke-width="0.8" opacity="0"/></svg>';
    tl.innerHTML = s;
    geo = { X0: X0, X1: X1 };
  }

  function setA(id) { document.querySelectorAll(".g").forEach(function (g) { g.style.opacity = (!id || g.getAttribute("data-id") === id) ? 1 : 0.15; }); }
  function setAChave(ch) { document.querySelectorAll("#map .g").forEach(function (g) { g.style.opacity = (!ch || g.getAttribute("data-chave") === ch) ? 1 : 0.15; }); }
  function label(id, e) { var b = app.getBoundingClientRect(); tip.textContent = id; tip.style.display = "block"; tip.style.left = (e.clientX - b.left + 14) + "px"; tip.style.top = (e.clientY - b.top - 34) + "px"; }
  function off() { setA(null); tip.style.display = "none"; lista(); var c = document.getElementById("cur"); if (c) c.setAttribute("opacity", 0); }
  svg.querySelectorAll(".g").forEach(function (g) {
    g.addEventListener("mouseenter", function () {
      var ch = g.getAttribute("data-chave"), il = porChave[ch];
      if (il.id === "BENIGN") { setAChave(ch); } else { setA(il.id); }
      detalhe(il);
    });
    g.addEventListener("mousemove", function (e) { label(g.getAttribute("data-id"), e); });
    g.addEventListener("mouseleave", off);
  });
  tl.addEventListener("mousemove", function (e) {
    if (!T || !geo) return;
    var b = tl.getBoundingClientRect(), vx = e.clientX - b.left - 8;
    if (vx < geo.X0 || vx > geo.X1) { off(); return; }
    var mm = T.t0 + (vx - geo.X0) / (geo.X1 - geo.X0) * (T.t1 - T.t0), id = "BENIGN";
    ordem().forEach(function (t) { T.seg[t].forEach(function (r) { if (mm >= r[0] && mm <= r[1] && id === "BENIGN") id = t; }); });
    var c = document.getElementById("cur"); c.setAttribute("x1", vx); c.setAttribute("x2", vx); c.setAttribute("opacity", 1);
    setA(id); label(id, e);
    if (id === "BENIGN") { lista(); } else { detalhe(porChave[id]); }
  });
  tl.addEventListener("mouseleave", off);
  window.addEventListener("resize", desenharTL);
  desenharTL();
})();
</script>
</body>
</html>
"""


def gerar_html():
    if not os.path.exists(MEDIDAS):
        sys.exit(f"{MEDIDAS} nao existe. Rode primeiro: python painel_grafos.py --medir")
    with open(MEDIDAS, encoding="utf-8") as f:
        dados = json.load(f)
    js = json.dumps(dados, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    with open(SAIDA, "w", encoding="utf-8") as f:
        f.write(HTML.replace("__DADOS__", js))
    print(f"gerado: {SAIDA} ({os.path.getsize(SAIDA) / 1e6:.2f} MB)")


if __name__ == "__main__":
    if "--verificar" in sys.argv:
        passo_verificar()
        sys.exit(0)
    if "--medir" in sys.argv:
        passo_medir()
    gerar_html()
