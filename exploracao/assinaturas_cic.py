#!/usr/bin/env python3
"""Assinaturas de trafego do CIC-DDoS2019: um cartao por tipo, com mini-grafo e metricas medidas.

Passo 1 (demora; le os CSVs completos; precisa do duckdb do venv):
    source ~/venv-ddos/bin/activate
    cd ~/ddos-dados && python assinaturas_cic.py --medir

Passo 2 (so gera o HTML a partir das medidas; segundos):
    cd ~/ddos-dados && python assinaturas_cic.py

Entradas : <BASE>/treino/*.csv  e  <BASE>/teste/*.csv   (so no passo 1)
Saidas   : <BASE>/assinaturas_cic.json  e  <BASE>/assinaturas_cic.html
"""
import glob
import json
import os
import random
import sys
from collections import Counter, defaultdict

BASE = os.environ.get("DDOS_BASE", os.path.expanduser("~/ddos-dados"))
MEDIDAS = os.path.join(BASE, "assinaturas_cic.json")
SAIDA = os.path.join(BASE, "assinaturas_cic.html")
N_ARESTAS = 150          # fluxos sorteados por tipo para desenhar o mini-grafo
LIMIAR_FIXA = 0.5        # porta "fixa" se concentrar pelo menos 50% dos fluxos
PROTO = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Taxonomia do CIC-DDoS2019: reflexao x exploracao. Portmap nao consta nela
# (agrupado em reflexao por nossa conta); BENIGN e o trafego normal.
REFLEXAO = {"DNS", "NTP", "LDAP", "MSSQL", "NetBIOS", "SNMP", "SSDP", "TFTP", "Portmap", "CharGen"}
EXPLORACAO = {"Syn", "UDP", "UDPLag"}


def familia(t):
    if t == "BENIGN":
        return "normal"
    if t in REFLEXAO:
        return "reflexao"
    if t in EXPLORACAO:
        return "exploracao"
    return "outros"


# --------------------------------------------------------------------------
# Passo 1: medir nos CSVs completos
# --------------------------------------------------------------------------
def medir_dia(con, dia):
    arquivos = sorted(glob.glob(os.path.join(BASE, dia, "*.csv")))
    if not arquivos:
        print(f"[{dia}] nenhum CSV em {os.path.join(BASE, dia)}")
        return None
    n = Counter()
    ips_o, ips_d = defaultdict(set), defaultdict(set)
    sp, dp, pr = defaultdict(Counter), defaultdict(Counter), defaultdict(Counter)
    arestas = defaultdict(list)
    precisa = ["Label", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"]

    for arq in arquivos:
        print(f"[{dia}] lendo {os.path.basename(arq)} ...", flush=True)
        leitura = f"read_csv_auto('{arq}', header=true, ignore_errors=true)"
        cols = [r[0] for r in con.sql(f"DESCRIBE SELECT * FROM {leitura}").fetchall()]
        m = {c.strip(): c for c in cols}
        falt = [c for c in precisa if c not in m]
        if falt:
            print(f"   colunas ausentes {falt}; arquivo ignorado")
            continue
        con.sql(f"""
            CREATE OR REPLACE TEMP TABLE f AS
            SELECT regexp_replace(TRIM(CAST("{m['Label']}" AS VARCHAR)), '^DrDoS_', '') AS tipo,
                   CAST("{m['Source IP']}" AS VARCHAR) AS sip,
                   TRY_CAST("{m['Source Port']}" AS BIGINT) AS sport,
                   CAST("{m['Destination IP']}" AS VARCHAR) AS dip,
                   TRY_CAST("{m['Destination Port']}" AS BIGINT) AS dport,
                   TRY_CAST("{m['Protocol']}" AS BIGINT) AS proto
            FROM {leitura}
        """)
        for t, c in con.sql("SELECT tipo, COUNT(*) FROM f GROUP BY 1").fetchall():
            n[t] += int(c)
        for t, ip in con.sql("SELECT DISTINCT tipo, sip FROM f WHERE sip IS NOT NULL").fetchall():
            ips_o[t].add(ip)
        for t, ip in con.sql("SELECT DISTINCT tipo, dip FROM f WHERE dip IS NOT NULL").fetchall():
            ips_d[t].add(ip)
        for t, p, c in con.sql("SELECT tipo, sport, COUNT(*) FROM f WHERE sport IS NOT NULL GROUP BY 1, 2").fetchall():
            sp[t][int(p)] += int(c)
        for t, p, c in con.sql("SELECT tipo, dport, COUNT(*) FROM f WHERE dport IS NOT NULL GROUP BY 1, 2").fetchall():
            dp[t][int(p)] += int(c)
        for t, p, c in con.sql("SELECT tipo, proto, COUNT(*) FROM f WHERE proto IS NOT NULL GROUP BY 1, 2").fetchall():
            pr[t][int(p)] += int(c)
        for t in [r[0] for r in con.sql("SELECT DISTINCT tipo FROM f").fetchall()]:
            q = t.replace("'", "''")
            linhas = con.sql(f"""
                SELECT sip, sport, dip, dport
                FROM (SELECT sip, sport, dip, dport FROM f WHERE tipo = '{q}')
                USING SAMPLE {N_ARESTAS} ROWS
            """).fetchall()
            arestas[t].extend(linhas)

    rnd = random.Random(42)
    tipos = []
    for t in sorted(n, key=lambda x: (x != "BENIGN", -n[x])):
        def topo(c):
            tot = sum(c.values())
            if not tot:
                return None
            p, k = c.most_common(1)[0]
            return [int(p), round(k / tot, 4), len(c)]
        ar = arestas[t]
        rnd.shuffle(ar)
        ar = ar[:N_ARESTAS]
        ids, nos, ligas = {}, [], []
        for sip, sport, dip, dport in ar:
            ends = []
            for ip, port in ((sip, sport), (dip, dport)):
                k = f"{ip}:{port}"
                if k not in ids:
                    ids[k] = len(nos)
                    nos.append(k)
                ends.append(ids[k])
            ligas.append(ends)
        proto = None
        if pr[t]:
            p, k = pr[t].most_common(1)[0]
            proto = [PROTO.get(p, str(p)), round(k / sum(pr[t].values()), 4)]
        tipos.append({
            "t": t, "fam": familia(t), "n": n[t],
            "ips_o": len(ips_o[t]), "ips_d": len(ips_d[t]),
            "sp": topo(sp[t]), "dp": topo(dp[t]), "proto": proto,
            "nos": nos, "arestas": ligas,
        })
    return {"tipos": tipos}


def assinatura(o):
    """Resumo comparavel entre dias: protocolo e portas dominantes (so se fixas)."""
    sp = o["sp"][0] if o["sp"] and o["sp"][1] >= LIMIAR_FIXA else None
    dp = o["dp"][0] if o["dp"] and o["dp"][1] >= LIMIAR_FIXA else None
    return (o["proto"][0] if o["proto"] else None, sp, dp)


def descrever(o):
    def porta(x):
        if not x:
            return "sem dado"
        return f"fixa {x[0]}" if x[1] >= LIMIAR_FIXA else "variável"
    pr = o["proto"][0] if o["proto"] else "?"
    return f"{pr}, origem {porta(o['sp'])}, destino {porta(o['dp'])}"


def comparar_dias(saida):
    if "treino" not in saida or "teste" not in saida:
        for d in saida.values():
            for o in d["tipos"]:
                o["confere"] = {"estado": "so", "texto": ""}
        return
    por = {d: {o["t"]: o for o in saida[d]["tipos"]} for d in saida}
    for d, outro in (("treino", "teste"), ("teste", "treino")):
        for o in saida[d]["tipos"]:
            par = por[outro].get(o["t"])
            if par is None:
                o["confere"] = {"estado": "so", "texto": f"só existe no conjunto de {d}"}
            else:
                igual = assinatura(o) == assinatura(par)
                o["confere"] = {
                    "estado": "igual" if igual else "difere",
                    "texto": f"{d}: {descrever(o)}; {outro}: {descrever(par)}",
                }


def passo_medir():
    import duckdb
    con = duckdb.connect()
    con.sql("SET memory_limit='1GB'; SET threads=2;")
    saida = {}
    for dia in ("treino", "teste"):
        r = medir_dia(con, dia)
        if r:
            saida[dia] = r
    if not saida:
        sys.exit("Nada medido. Confira as pastas treino/ e teste/.")
    comparar_dias(saida)
    with open(MEDIDAS, "w", encoding="utf-8") as f:
        json.dump(saida, f, ensure_ascii=False, separators=(",", ":"))
    print(f"gerado: {MEDIDAS}")


# --------------------------------------------------------------------------
# Passo 2: HTML
# --------------------------------------------------------------------------
COLORS = {
    "BENIGN": "#e6f0ff", "Syn": "#ff4d6d", "UDP": "#ffb454", "UDPLag": "#ffe066",
    "LDAP": "#b388ff", "MSSQL": "#4fc3ff", "NetBIOS": "#ff7a59", "Portmap": "#4ade80",
    "DNS": "#38bdf8", "NTP": "#f472b6", "SNMP": "#c4b5fd", "SSDP": "#fb923c", "TFTP": "#2dd4bf",
}

HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assinaturas de tráfego, CIC-DDoS2019</title>
<style>
  :root { --ink:#e8ecff; --soft:#9aa6d6; --line:rgba(140,160,255,0.18); --panel:rgba(10,14,40,0.72); --accent:#7aa2ff; }
  * { box-sizing: border-box; }
  body { margin: 0; color: var(--ink); font-family: "Ubuntu","Segoe UI",system-ui,sans-serif; font-size: 0.9rem; min-height: 100vh;
    background: radial-gradient(ellipse 70% 50% at 12% 5%, rgba(38,66,190,0.45) 0%, transparent 60%),
                radial-gradient(ellipse 60% 50% at 90% 95%, rgba(118,40,190,0.4) 0%, transparent 62%), #070a1f;
    background-attachment: fixed; }
  #app { max-width: 1300px; margin: 0 auto; padding: 22px 24px 32px; }
  header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 6px; }
  h1 { margin: 0; font-size: 1.5rem; font-weight: 300; }
  h2 { margin: 26px 0 12px; font-size: 1rem; font-weight: 500; }
  h2 small { color: var(--soft); font-weight: 400; margin-left: 8px; }
  .sub { margin: 5px 0 0; color: var(--soft); font-size: 0.85rem; max-width: 70ch; }
  .seg { display: inline-flex; border: 1px solid var(--line); border-radius: 999px; background: var(--panel); padding: 3px; }
  .seg button { font: inherit; color: var(--soft); background: transparent; border: 0; padding: 6px 15px; border-radius: 999px; cursor: pointer; }
  .seg button[aria-pressed="true"] { color: #fff; background: rgba(122,162,255,0.28); }
  button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(290px, 1fr)); gap: 16px; }
  .card { border: 1px solid var(--line); border-radius: 12px; background: var(--panel); padding: 14px 16px 12px; min-width: 0; }
  .top { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex: none; }
  .nome { font-size: 1rem; font-weight: 500; }
  .n { color: var(--soft); font-size: 0.8rem; font-variant-numeric: tabular-nums; }
  .badge { margin-left: auto; font-size: 0.72rem; padding: 2px 9px; border-radius: 999px; border: 1px solid var(--line); color: var(--soft); white-space: nowrap; }
  .badge.igual { color: #86efac; border-color: rgba(134,239,172,0.4); }
  .badge.difere { color: #fcd34d; border-color: rgba(252,211,77,0.4); }
  canvas { width: 100%; height: 130px; display: block; border-radius: 8px; background: rgba(5,8,28,0.55); }
  .hub { color: var(--soft); font-size: 0.75rem; margin: 6px 0 8px; min-height: 1.1em; font-variant-numeric: tabular-nums; }
  dl { margin: 0; display: grid; grid-template-columns: auto 1fr; gap: 3px 12px; font-size: 0.82rem; }
  dt { color: var(--soft); }
  dd { margin: 0; text-align: right; font-variant-numeric: tabular-nums; }
  .vazio { color: var(--soft); margin: 0; }
</style>
</head>
<body>
<div id="app">
  <header>
    <div>
      <h1>Assinaturas de tráfego no CIC-DDoS2019</h1>
      <p class="sub" id="sub"></p>
    </div>
    <div class="seg" role="group" aria-label="Conjunto de dados">
      <button type="button" data-dia="treino" aria-pressed="true">Treino (01-12)</button>
      <button type="button" data-dia="teste" aria-pressed="false">Teste (03-11)</button>
    </div>
  </header>
  <div id="corpo"></div>
</div>
<script id="dados" type="application/json">__DADOS__</script>
<script>
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("dados").textContent);
  var COLORS = __CORES__, FALLBACK = ["#f9a8d4", "#a5b4fc", "#fcd34d", "#6ee7b7", "#fda4af"];
  var FAMS = [["reflexao", "Reflexão e amplificação"], ["exploracao", "Exploração"], ["normal", "Tráfego normal"], ["outros", "Outros"]];
  var nf = new Intl.NumberFormat("pt-BR");
  function color(t) { if (COLORS[t]) return COLORS[t]; var h = 0; for (var i = 0; i < t.length; i++) h += t.charCodeAt(i); return FALLBACK[h % FALLBACK.length]; }
  function el(id) { return document.getElementById(id); }
  function pct(v) { return Math.round(v * 100) + "%"; }
  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }

  function rng(seed) { var s = seed >>> 0; return function () { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; }; }
  function layout(n, edges, w, h) {
    var r = rng(7), x = [], y = [], i, it, k, dx, dy, d, f;
    for (i = 0; i < n; i++) { x.push(r() * w); y.push(r() * h); }
    if (n < 2) { return { x: [w / 2], y: [h / 2] }; }
    k = Math.sqrt(w * h / n) * 0.8;
    var T = w / 6;
    for (it = 0; it < 90; it++) {
      var fx = new Array(n).fill(0), fy = new Array(n).fill(0), j;
      for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) {
        dx = x[i] - x[j]; dy = y[i] - y[j]; d = Math.sqrt(dx * dx + dy * dy) + 0.01; f = k * k / d;
        fx[i] += dx / d * f; fy[i] += dy / d * f; fx[j] -= dx / d * f; fy[j] -= dy / d * f;
      }
      edges.forEach(function (e) {
        var a = e[0], b = e[1]; dx = x[a] - x[b]; dy = y[a] - y[b]; d = Math.sqrt(dx * dx + dy * dy) + 0.01; f = d * d / k;
        fx[a] -= dx / d * f; fy[a] -= dy / d * f; fx[b] += dx / d * f; fy[b] += dy / d * f;
      });
      for (i = 0; i < n; i++) {
        fx[i] += (w / 2 - x[i]) * 0.02; fy[i] += (h / 2 - y[i]) * 0.02;
        d = Math.sqrt(fx[i] * fx[i] + fy[i] * fy[i]) + 0.01; f = Math.min(d, T);
        x[i] += fx[i] / d * f; y[i] += fy[i] / d * f;
      }
      T *= 0.95;
    }
    var x0 = Math.min.apply(null, x), x1 = Math.max.apply(null, x), y0 = Math.min.apply(null, y), y1 = Math.max.apply(null, y), p = 10;
    for (i = 0; i < n; i++) {
      x[i] = p + (x[i] - x0) / Math.max(x1 - x0, 1e-6) * (w - 2 * p);
      y[i] = p + (y[i] - y0) / Math.max(y1 - y0, 1e-6) * (h - 2 * p);
    }
    return { x: x, y: y };
  }

  function porta(a) { return a ? (a[1] >= 0.5 ? "fixa " + a[0] + " (" + pct(a[1]) + ")" : "variável (" + nf.format(a[2]) + " portas)") : "sem dado"; }

  function card(o) {
    var c = document.createElement("div"); c.className = "card";
    var badge = "";
    if (o.confere && o.confere.estado !== "so") {
      badge = '<span class="badge ' + o.confere.estado + '" title="' + esc(o.confere.texto) + '">' + (o.confere.estado === "igual" ? "repete no outro dia" : "difere no outro dia") + "</span>";
    } else if (o.confere) { badge = '<span class="badge" title="' + esc(o.confere.texto) + '">só neste dia</span>'; }
    c.innerHTML = '<div class="top"><span class="dot" style="background:' + color(o.t) + '"></span><span class="nome">' + esc(o.t) + '</span><span class="n">' + nf.format(o.n) + " fluxos</span>" + badge + "</div>" +
      '<canvas></canvas><div class="hub"></div>' +
      "<dl><dt>IPs de origem</dt><dd>" + nf.format(o.ips_o) + "</dd><dt>IPs de destino</dt><dd>" + nf.format(o.ips_d) + "</dd>" +
      "<dt>Porta de origem</dt><dd>" + porta(o.sp) + "</dd><dt>Porta de destino</dt><dd>" + porta(o.dp) + "</dd>" +
      "<dt>Protocolo</dt><dd>" + (o.proto ? o.proto[0] + " (" + pct(o.proto[1]) + ")" : "sem dado") + "</dd></dl>";
    return c;
  }
  function desenhar(cv, o) {
    var w = cv.clientWidth, h = cv.clientHeight, dpr = Math.min(window.devicePixelRatio || 1, 2);
    cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    var g = cv.getContext("2d"); g.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (!o.nos.length) return;
    var N = o.nos.length, p = layout(N, o.arestas, w, h), deg = new Array(N).fill(0), asSrc = new Array(N).fill(0), asDst = new Array(N).fill(0), c = color(o.t);
    g.strokeStyle = c; g.globalAlpha = 0.28; g.lineWidth = 0.8;
    o.arestas.forEach(function (e) { deg[e[0]]++; deg[e[1]]++; asSrc[e[0]]++; asDst[e[1]]++; g.beginPath(); g.moveTo(p.x[e[0]], p.y[e[0]]); g.lineTo(p.x[e[1]], p.y[e[1]]); g.stroke(); });
    g.globalAlpha = 1; g.fillStyle = c; g.lineWidth = 1.2;
    var hub = 0;
    function no(i, r) {
      g.beginPath(); g.arc(p.x[i], p.y[i], r, 0, 6.2832);
      if (asDst[i] > 0 && asSrc[i] === 0) { g.fillStyle = "rgba(5,8,28,1)"; g.fill(); g.stroke(); } else { g.fillStyle = c; g.fill(); }
    }
    deg.forEach(function (d, i) { if (d > deg[hub]) hub = i; no(i, 2.2); });
    g.lineWidth = 1.8; no(hub, 5.5);
    var lab = cv.parentNode.querySelector(".hub"), papel = asSrc[hub] >= asDst[hub] ? "origem" : "destino";
    lab.textContent = "Maior nó na amostra: " + o.nos[hub] + ", como " + papel + " em " + deg[hub] + " de " + o.arestas.length + " fluxos";
  }

  var dia = "treino";
  function render() {
    var R = D[dia], corpo = el("corpo"); corpo.innerHTML = "";
    el("sub").textContent = "Medido nos CSVs completos do conjunto de " + dia + ", em ambiente de laboratório: em redes reais o comportamento varia. Cada mini-grafo usa até 150 fluxos sorteados: os nós são IP:porta, cheios quando atuam como origem e vazados quando atuam como destino.";
    var pend = [];
    FAMS.forEach(function (f) {
      var lista = R.tipos.filter(function (o) { return o.fam === f[0]; });
      if (!lista.length) return;
      var h = document.createElement("h2"); h.textContent = f[1];
      if (f[0] === "reflexao") { var s = document.createElement("small"); s.textContent = "Portmap não consta na taxonomia do CIC e foi agrupado aqui"; if (lista.some(function (o) { return o.t === "Portmap"; })) h.appendChild(s); }
      corpo.appendChild(h);
      var grid = document.createElement("div"); grid.className = "grid"; corpo.appendChild(grid);
      lista.forEach(function (o) { var c = card(o); grid.appendChild(c); pend.push([c.querySelector("canvas"), o]); });
    });
    pend.forEach(function (p) { desenhar(p[0], p[1]); });
  }
  document.querySelectorAll(".seg button").forEach(function (b) {
    b.addEventListener("click", function () {
      var d = b.getAttribute("data-dia"); if (!D[d]) return; dia = d;
      document.querySelectorAll(".seg button").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      render();
    });
  });
  var timer; window.addEventListener("resize", function () { clearTimeout(timer); timer = setTimeout(render, 200); });
  dia = D.treino ? "treino" : Object.keys(D)[0];
  render();
})();
</script>
</body>
</html>
"""


def gerar_html():
    if not os.path.exists(MEDIDAS):
        sys.exit(f"{MEDIDAS} nao existe. Rode primeiro: python assinaturas_cic.py --medir")
    with open(MEDIDAS, encoding="utf-8") as f:
        dados = json.load(f)
    js = json.dumps(dados, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    html = HTML.replace("__DADOS__", js).replace("__CORES__", json.dumps(COLORS))
    with open(SAIDA, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"gerado: {SAIDA} ({os.path.getsize(SAIDA) / 1e6:.2f} MB)")


if __name__ == "__main__":
    if "--medir" in sys.argv:
        passo_medir()
    gerar_html()
