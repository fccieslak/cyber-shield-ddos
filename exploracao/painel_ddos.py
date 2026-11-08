#!/usr/bin/env python3
"""Painel de analise de ataques DDoS, inspirado no SecGrid, alimentado pelos CSVs do CIC-DDoS2019.

Passo 1 (demora; le os CSVs completos; precisa de duckdb, pandas e scikit-learn do venv):
    source ~/venv-ddos/bin/activate
    cd ~/ddos-dados && python painel_ddos.py --agregar

Passo 2 (so gera o HTML a partir dos agregados; segundos):
    cd ~/ddos-dados && python painel_ddos.py

Entradas : <BASE>/treino/*.csv, <BASE>/teste/*.csv   (passo 1)
           <BASE>/amostra_fluxos.csv                  (passo 1, para a parte de IA; opcional)
Saidas   : <BASE>/agregados_painel.json  e  <BASE>/painel_ddos.html
"""
import glob
import json
import os
import sys

BASE = os.environ.get("DDOS_BASE", os.path.expanduser("~/ddos-dados"))
AGREGADOS = os.path.join(BASE, "agregados_painel.json")
AMOSTRA = os.path.join(BASE, "amostra_fluxos.csv")
SAIDA = os.path.join(BASE, "painel_ddos.html")
SEMENTE = 42
TOP_ARQ = 25      # portas e IPs guardados por tipo, em cada arquivo
TOP_FINAL = 8     # portas e IPs mostrados no painel

FEATURES_IA = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Average Packet Size",
    "SYN Flag Count", "ACK Flag Count",
]
COLORS = {
    "BENIGN": "#e6f0ff", "Syn": "#ff4d6d", "UDP": "#ffb454", "UDPLag": "#ffe066",
    "LDAP": "#b388ff", "MSSQL": "#4fc3ff", "NetBIOS": "#ff7a59", "Portmap": "#4ade80",
    "DNS": "#38bdf8", "NTP": "#f472b6", "SNMP": "#c4b5fd", "SSDP": "#fb923c",
    "TFTP": "#2dd4bf",
}


# --------------------------------------------------------------------------
# Passo 1a: agregacao dos CSVs completos com DuckDB
# --------------------------------------------------------------------------
def agregar_csvs():
    import duckdb

    con = duckdb.connect()
    con.sql("SET memory_limit='1GB'; SET threads=2;")
    precisa = ["Label", "Timestamp", "Source IP", "Destination Port",
               "Total Fwd Packets", "Total Backward Packets"]
    saida = {}
    for dia in ("treino", "teste"):
        arquivos = sorted(glob.glob(os.path.join(BASE, dia, "*.csv")))
        if not arquivos:
            print(f"[{dia}] nenhum CSV em {os.path.join(BASE, dia)}")
            continue
        tl, tot, portas, ips = {}, {}, {}, {}
        for arq in arquivos:
            print(f"[{dia}] lendo {os.path.basename(arq)} ...", flush=True)
            leitura = f"read_csv_auto('{arq}', header=true, ignore_errors=true)"
            cols = [r[0] for r in con.sql(f"DESCRIBE SELECT * FROM {leitura}").fetchall()]
            mapa = {c.strip(): c for c in cols}
            falt = [c for c in precisa if c not in mapa]
            if falt:
                print(f"   colunas ausentes {falt}; arquivo ignorado")
                continue
            con.sql(f"""
                CREATE OR REPLACE TEMP TABLE f AS
                SELECT regexp_replace(TRIM(CAST("{mapa['Label']}" AS VARCHAR)), '^DrDoS_', '') AS tipo,
                       TRY_CAST(CAST("{mapa['Timestamp']}" AS VARCHAR) AS TIMESTAMP) AS ts,
                       CAST("{mapa['Source IP']}" AS VARCHAR) AS sip,
                       TRY_CAST("{mapa['Destination Port']}" AS BIGINT) AS dport,
                       COALESCE(TRY_CAST("{mapa['Total Fwd Packets']}" AS DOUBLE), 0)
                     + COALESCE(TRY_CAST("{mapa['Total Backward Packets']}" AS DOUBLE), 0) AS pk
                FROM {leitura}
            """)
            for tipo, t, fl, pk in con.sql("""
                SELECT tipo, CAST(epoch(date_trunc('minute', ts)) / 60 AS BIGINT) AS t,
                       COUNT(*) AS fl, CAST(SUM(pk) AS BIGINT) AS pk
                FROM f WHERE ts IS NOT NULL GROUP BY 1, 2
            """).fetchall():
                d = tl.setdefault(tipo, {}).setdefault(int(t), [0, 0])
                d[0] += int(fl); d[1] += int(pk or 0)
            for tipo, fl, pk in con.sql(
                    "SELECT tipo, COUNT(*), CAST(SUM(pk) AS BIGINT) FROM f GROUP BY 1").fetchall():
                d = tot.setdefault(tipo, [0, 0]); d[0] += int(fl); d[1] += int(pk or 0)
            for tipo, p, n in con.sql(f"""
                SELECT tipo, dport, COUNT(*) AS n FROM f WHERE dport IS NOT NULL GROUP BY 1, 2
                QUALIFY row_number() OVER (PARTITION BY tipo ORDER BY n DESC) <= {TOP_ARQ}
            """).fetchall():
                portas.setdefault(int(p), {}).setdefault(tipo, 0)
                portas[int(p)][tipo] += int(n)
            for tipo, ip, n in con.sql(f"""
                SELECT tipo, sip, COUNT(*) AS n FROM f WHERE sip IS NOT NULL GROUP BY 1, 2
                QUALIFY row_number() OVER (PARTITION BY tipo ORDER BY n DESC) <= {TOP_ARQ}
            """).fetchall():
                ips.setdefault(ip, {}).setdefault(tipo, 0)
                ips[ip][tipo] += int(n)

        if not tot:
            continue

        def topo(d, chave):
            lista = [{chave: k, "tot": sum(v.values()), "por": v} for k, v in d.items()]
            lista.sort(key=lambda o: -o["tot"])
            return lista[:TOP_FINAL]

        tipos = sorted(tot, key=lambda t: ((t != "BENIGN"), -tot[t][0]))
        todos_t = [t for v in tl.values() for t in v]
        saida[dia] = {
            "tipos": [{"t": t, "fluxos": tot[t][0], "pacotes": tot[t][1]} for t in tipos],
            "tl": {t: sorted([[m, v[0], v[1]] for m, v in tl.get(t, {}).items()]) for t in tipos},
            "ports": topo(portas, "p"),
            "ips": topo(ips, "ip"),
            "meta": {"fluxos": sum(v[0] for v in tot.values()),
                     "pacotes": sum(v[1] for v in tot.values()),
                     "t0": min(todos_t) if todos_t else None,
                     "t1": max(todos_t) if todos_t else None},
            "ia": None,
        }
    return saida


# --------------------------------------------------------------------------
# Passo 1b: IA (Random Forest) na amostra, acerto por tipo
# --------------------------------------------------------------------------
def ia_por_dia(saida):
    if not os.path.exists(AMOSTRA):
        print(f"{AMOSTRA} nao existe: o painel de IA ficara de fora "
              f"(gere com: python gerador_fluxos.py --amostrar)")
        return
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, confusion_matrix
    from sklearn.model_selection import train_test_split

    df = pd.read_csv(AMOSTRA)
    df.columns = [c.strip() for c in df.columns]
    falt = [c for c in ["dia", "tipo"] + FEATURES_IA if c not in df.columns]
    if falt:
        print(f"amostra sem colunas {falt}: IA ignorada")
        return
    df[FEATURES_IA] = df[FEATURES_IA].apply(pd.to_numeric, errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan)
    for dia, bloco in saida.items():
        d = df[df["dia"] == dia].reset_index(drop=True)
        if d.empty:
            continue
        X = d[FEATURES_IA]
        X = X.fillna(X.median(numeric_only=True)).fillna(0)
        y = d["tipo"].astype(str).to_numpy(dtype=object)
        cont = pd.Series(y).value_counts()
        estrat = y if (cont >= 2).all() else None
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25,
                                              random_state=SEMENTE, stratify=estrat)
        rf = RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced",
                                    n_jobs=2, random_state=SEMENTE).fit(Xtr, ytr)
        pred = rf.predict(Xte)
        rotulos = sorted(set(yte) | set(pred))
        cm = confusion_matrix(yte, pred, labels=rotulos)
        linhas = []
        for i, t in enumerate(rotulos):
            suporte = int(cm[i].sum())
            if suporte == 0:
                continue
            rec = float(cm[i, i] / suporte)
            fora = cm[i].copy(); fora[i] = 0
            conf = rotulos[int(fora.argmax())] if fora.sum() > 0 else None
            linhas.append({"t": t, "rec": round(rec, 4), "n": suporte, "conf": conf})
        linhas.sort(key=lambda o: ((o["t"] != "BENIGN"), -o["n"]))
        bloco["ia"] = {"acc": round(float(accuracy_score(yte, pred)), 4), "tipos": linhas}
        print(f"[{dia}] IA: acerto geral {bloco['ia']['acc']:.3f}", flush=True)


def passo_agregar():
    saida = agregar_csvs()
    if not saida:
        sys.exit("Nenhum dado agregado. Confira as pastas treino/ e teste/.")
    ia_por_dia(saida)
    with open(AGREGADOS, "w", encoding="utf-8") as f:
        json.dump(saida, f, ensure_ascii=False, separators=(",", ":"))
    print(f"gerado: {AGREGADOS}")


# --------------------------------------------------------------------------
# Passo 2: HTML
# --------------------------------------------------------------------------
HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Painel de ataques DDoS, CIC-DDoS2019</title>
<style>
  :root { --ink:#e8ecff; --soft:#9aa6d6; --line:rgba(140,160,255,0.18); --panel:rgba(10,14,40,0.72); --accent:#7aa2ff; }
  * { box-sizing: border-box; }
  body { margin: 0; color: var(--ink); font-family: "Ubuntu","Segoe UI",system-ui,sans-serif; font-size: 0.9rem; min-height: 100vh;
    background: radial-gradient(ellipse 70% 50% at 12% 5%, rgba(38,66,190,0.45) 0%, transparent 60%),
                radial-gradient(ellipse 60% 50% at 90% 95%, rgba(118,40,190,0.4) 0%, transparent 62%), #070a1f;
    background-attachment: fixed; }
  #app { max-width: 1400px; margin: 0 auto; padding: 20px 24px 28px; display: grid; gap: 16px; }
  header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; }
  h1 { margin: 0; font-size: 1.5rem; font-weight: 300; }
  h2 { margin: 0 0 12px; font-size: 0.95rem; font-weight: 500; }
  .sub { margin: 5px 0 0; color: var(--soft); font-size: 0.85rem; }
  .seg { display: inline-flex; border: 1px solid var(--line); border-radius: 999px; background: var(--panel); padding: 3px; }
  .seg button { font: inherit; color: var(--soft); background: transparent; border: 0; padding: 6px 15px; border-radius: 999px; cursor: pointer; }
  .seg button[aria-pressed="true"] { color: #fff; background: rgba(122,162,255,0.28); }
  button:focus-visible, select:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  #metrics { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 12px; }
  .m { border: 1px solid var(--line); border-radius: 12px; background: var(--panel); padding: 12px 16px; }
  .m .k { color: var(--soft); font-size: 0.8rem; }
  .m .v.small { font-size: 1.05rem; padding-top: 5px; }
  .m .v { font-size: 1.35rem; font-weight: 300; margin-top: 2px; font-variant-numeric: tabular-nums; }
  .grid { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 16px; }
  .box { border: 1px solid var(--line); border-radius: 12px; background: var(--panel); padding: 14px 16px; min-width: 0; }
  .wide { grid-column: span 2; }
  .head { display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
  .head h2 { margin: 0; }
  .ctl { display: flex; gap: 10px; align-items: center; color: var(--soft); font-size: 0.82rem; }
  select { font: inherit; color: var(--ink); background: rgba(20,26,70,0.9); border: 1px solid var(--line); border-radius: 8px; padding: 4px 8px; }
  #chips { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
  .chip { display: inline-flex; align-items: center; gap: 7px; font: inherit; font-size: 0.82rem; color: var(--ink); background: transparent;
          border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px; cursor: pointer; }
  .chip[aria-pressed="false"] { opacity: 0.35; }
  .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex: none; }
  .cwrap { position: relative; }
  #tl { width: 100%; height: 280px; display: block; }
  #tip { position: absolute; display: none; pointer-events: none; z-index: 5; padding: 7px 10px; border: 1px solid var(--line);
         border-radius: 8px; background: rgba(8,12,36,0.94); font-size: 0.78rem; line-height: 1.5; font-variant-numeric: tabular-nums; white-space: nowrap; }
  .donut { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }
  .legend { list-style: none; margin: 0; padding: 0; flex: 1; min-width: 150px; }
  .legend li { display: flex; align-items: center; gap: 8px; padding: 3px 0; font-size: 0.82rem; }
  .legend .n { margin-left: auto; color: var(--soft); font-variant-numeric: tabular-nums; }
  .row { display: grid; grid-template-columns: 96px 1fr 58px; gap: 10px; align-items: center; margin-bottom: 9px; font-size: 0.82rem; }
  .row.ia { grid-template-columns: 150px 1fr 54px; }
  .row .l { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .row .l small { display: block; color: var(--soft); font-size: 0.72rem; }
  .row .tr { height: 8px; border-radius: 4px; background: rgba(140,160,255,0.1); display: flex; overflow: hidden; }
  .row .tr i { display: block; height: 100%; }
  .row .v { text-align: right; color: var(--soft); font-variant-numeric: tabular-nums; }
  .none { color: var(--soft); margin: 0; }
  @media (max-width: 1000px) { .grid { grid-template-columns: 1fr; } .wide { grid-column: auto; } #metrics { grid-template-columns: repeat(2, minmax(0,1fr)); } }
</style>
</head>
<body>
<div id="app">
  <header>
    <div><h1>Painel de ataques DDoS</h1><p class="sub" id="sub"></p></div>
    <div class="seg" role="group" aria-label="Conjunto de dados">
      <button type="button" data-dia="treino" aria-pressed="true">Treino (01-12)</button>
      <button type="button" data-dia="teste" aria-pressed="false">Teste (03-11)</button>
    </div>
  </header>

  <section id="metrics"></section>

  <section class="grid">
    <div class="box wide">
      <div class="head">
        <h2>Tráfego ao longo do tempo</h2>
        <div class="ctl">
          <select id="metric" aria-label="Métrica"><option value="fluxos">Fluxos por minuto</option><option value="pacotes">Pacotes por minuto</option></select>
          <label><input type="checkbox" id="log"> escala log</label>
        </div>
      </div>
      <div id="chips" role="group" aria-label="Tipos de tráfego"></div>
      <div class="cwrap"><canvas id="tl" aria-label="Linha do tempo do tráfego por tipo"></canvas><div id="tip"></div></div>
    </div>
    <div class="box"><h2>Proporção de fluxos por tipo</h2><div class="donut"><canvas id="dn" width="150" height="150" style="width:150px;height:150px" aria-label="Proporção de fluxos por tipo"></canvas><ul class="legend" id="dnl"></ul></div></div>
    <div class="box"><h2>Portas de destino mais usadas</h2><div id="ports"></div></div>
    <div class="box"><h2>IPs de origem que mais enviam</h2><div id="ips"></div></div>
    <div class="box"><h2>Acerto da IA por tipo</h2><p class="sub" id="iasub" style="margin:-6px 0 10px"></p><div id="ia"></div></div>
  </section>
</div>
<script id="dados" type="application/json">__DADOS__</script>
<script>
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("dados").textContent);
  var COLORS = __CORES__, FALLBACK = ["#f9a8d4", "#a5b4fc", "#fcd34d", "#6ee7b7", "#fda4af"];
  var SERV = { 19: "CHARGEN", 53: "DNS", 69: "TFTP", 80: "HTTP", 111: "Portmap", 123: "NTP", 137: "NetBIOS", 161: "SNMP",
               389: "LDAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1900: "SSDP" };
  var nf = new Intl.NumberFormat("pt-BR"), nfc = new Intl.NumberFormat("pt-BR", { notation: "compact", maximumFractionDigits: 2 });
  function color(t) { if (COLORS[t]) return COLORS[t]; var h = 0; for (var i = 0; i < t.length; i++) h += t.charCodeAt(i); return FALLBACK[h % FALLBACK.length]; }
  function el(id) { return document.getElementById(id); }
  function p2(n) { return (n < 10 ? "0" : "") + n; }
  function fmtT(t) { var d = new Date(t * 60000); return p2(d.getUTCDate()) + "/" + p2(d.getUTCMonth() + 1) + " " + p2(d.getUTCHours()) + ":" + p2(d.getUTCMinutes()); }
  function fmtHM(t) { var d = new Date(t * 60000); return p2(d.getUTCHours()) + ":" + p2(d.getUTCMinutes()); }
  function pct(v) { return (v * 100).toFixed(1).replace(".", ",") + "%"; }

  var st = { dia: "treino", metric: "fluxos", log: false, off: {} }, R = null, info = null;

  function setDia(d) {
    if (!D[d]) return;
    st.dia = d; R = D[d]; st.off = {};
    document.querySelectorAll(".seg button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-dia") === d)); });
    el("sub").textContent = "CIC-DDoS2019, conjunto de " + d + ": " + R.tipos.length + " tipos de tráfego nos CSVs completos";
    metrics(); chips(); drawTL(); donut(); ports(); ips(); ia();
  }
  function metrics() {
    var m = R.meta, per = m.t0 === null ? "sem data" : fmtT(m.t0) + " a " + fmtT(m.t1);
    var dur = m.t0 === null ? "" : (function () { var h = (m.t1 - m.t0) / 60; return h >= 1 ? h.toFixed(1).replace(".", ",") + " h" : (m.t1 - m.t0) + " min"; })();
    var cards = [["Fluxos", nf.format(m.fluxos)], ["Pacotes", nfc.format(m.pacotes)], ["Tipos de tráfego", String(R.tipos.length)], ["Período" + (dur ? " (" + dur + ")" : ""), per]];
    el("metrics").innerHTML = cards.map(function (c) { return '<div class="m"><div class="k">' + c[0] + '</div><div class="v' + (c[0].indexOf("Período") === 0 ? " small" : "") + '">' + c[1] + "</div></div>"; }).join("");
  }
  function chips() {
    var box = el("chips"); box.innerHTML = "";
    R.tipos.forEach(function (o) {
      var b = document.createElement("button"); b.type = "button"; b.className = "chip";
      b.setAttribute("aria-pressed", String(!st.off[o.t]));
      b.innerHTML = '<span class="dot" style="background:' + color(o.t) + '"></span>' + o.t;
      b.addEventListener("click", function () { st.off[o.t] = !st.off[o.t]; chips(); drawTL(); });
      b.addEventListener("dblclick", function () { R.tipos.forEach(function (x) { st.off[x.t] = x.t !== o.t; }); chips(); drawTL(); });
      box.appendChild(b);
    });
  }
  function drawTL() {
    var cv = el("tl"), g = cv.getContext("2d"), w = cv.clientWidth, h = cv.clientHeight, dpr = Math.min(window.devicePixelRatio || 1, 2);
    cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
    g.font = "11px Ubuntu, 'Segoe UI', sans-serif";
    var mi = st.metric === "fluxos" ? 1 : 2, names = R.tipos.map(function (o) { return o.t; }).filter(function (t) { return !st.off[t]; });
    var tmin = Infinity, tmax = -Infinity, ymax = 0;
    names.forEach(function (n) { (R.tl[n] || []).forEach(function (p) { if (p[0] < tmin) tmin = p[0]; if (p[0] > tmax) tmax = p[0]; if (p[mi] > ymax) ymax = p[mi]; }); });
    if (!isFinite(tmin)) { info = null; g.fillStyle = "#9aa6d6"; g.fillText("Nenhum dado de tempo para os tipos selecionados", 60, 40); return; }
    if (tmax === tmin) tmax = tmin + 1;
    function nice(v) { if (v <= 0) return 1; var e = Math.pow(10, Math.floor(Math.log10(v))), f = v / e; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * e; }
    var Y = function (v) { return st.log ? Math.log10(1 + v) : v; }, ym = st.log ? Math.ceil(Y(ymax)) || 1 : nice(ymax);
    var L = 56, Rr = 12, T = 10, B = 26, pw = w - L - Rr, ph = h - T - B;
    info = { L: L, pw: pw, tmin: tmin, tmax: tmax, names: names, mi: mi };
    g.strokeStyle = "rgba(140,160,255,0.12)"; g.fillStyle = "#9aa6d6"; g.lineWidth = 1; g.textAlign = "right";
    var passos = st.log ? Math.max(1, Math.ceil(ym / 4)) : ym / 4, n = st.log ? Math.floor(ym / passos) : 4;
    for (var i = 0; i <= n; i++) {
      var val = passos * i, y = T + ph - ph * val / ym;
      g.beginPath(); g.moveTo(L, y); g.lineTo(L + pw, y); g.stroke();
      g.fillText(nfc.format(st.log ? Math.pow(10, val) : val), L - 6, y + 4);
    }
    g.textAlign = "center";
    for (var k = 0; k <= 5; k++) { var tt = tmin + (tmax - tmin) * k / 5; g.fillText(tmax - tmin > 1440 ? fmtT(tt) : fmtHM(tt), L + pw * k / 5, h - 8); }
    names.forEach(function (n) {
      var pts = R.tl[n] || [], c = color(n);
      g.strokeStyle = c; g.fillStyle = c; g.lineWidth = 1.6; g.beginPath();
      var prev = null;
      pts.forEach(function (p) {
        var x = L + (p[0] - tmin) / (tmax - tmin) * pw, yy = T + ph - Y(p[mi]) / ym * ph;
        if (prev === null || p[0] - prev > 2) g.moveTo(x, yy); else g.lineTo(x, yy);
        prev = p[0];
      });
      g.stroke();
      pts.forEach(function (p) {
        var x = L + (p[0] - tmin) / (tmax - tmin) * pw, yy = T + ph - Y(p[mi]) / ym * ph;
        g.beginPath(); g.arc(x, yy, 1.7, 0, 6.2832); g.fill();
      });
    });
  }
  var tip = el("tip");
  el("tl").addEventListener("mousemove", function (e) {
    if (!info) return;
    var b = e.target.getBoundingClientRect(), x = e.clientX - b.left, tm = info.tmin + (x - info.L) / info.pw * (info.tmax - info.tmin);
    if (x < info.L || x > info.L + info.pw) { tip.style.display = "none"; return; }
    var tol = Math.max(1, (info.tmax - info.tmin) / info.pw * 4), html = "<b>" + fmtT(Math.round(tm)) + "</b>", any = false;
    info.names.forEach(function (n) {
      var best = null, bd = Infinity;
      (R.tl[n] || []).forEach(function (p) { var d = Math.abs(p[0] - tm); if (d < bd) { bd = d; best = p; } });
      if (best && bd <= tol) { any = true; html += '<br><span class="dot" style="background:' + color(n) + '"></span> ' + n + ": " + nf.format(best[info.mi]); }
    });
    if (!any) { tip.style.display = "none"; return; }
    tip.innerHTML = html; tip.style.display = "block";
    tip.style.left = Math.min(x + 14, b.width - 190) + "px"; tip.style.top = "10px";
  });
  el("tl").addEventListener("mouseleave", function () { tip.style.display = "none"; });

  function donut() {
    var cv = el("dn"), g = cv.getContext("2d"), dpr = Math.min(window.devicePixelRatio || 1, 2), s = 150;
    cv.width = s * dpr; cv.height = s * dpr; g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, s, s);
    var total = R.tipos.reduce(function (a, o) { return a + o.fluxos; }, 0) || 1, a0 = -Math.PI / 2;
    R.tipos.forEach(function (o) {
      var a1 = a0 + o.fluxos / total * Math.PI * 2;
      g.beginPath(); g.arc(75, 75, 62, a0, Math.max(a0 + 0.004, a1 - 0.012)); g.strokeStyle = color(o.t); g.lineWidth = 18; g.stroke(); a0 = a1;
    });
    g.fillStyle = "#e8ecff"; g.textAlign = "center"; g.font = "300 18px Ubuntu, 'Segoe UI', sans-serif"; g.fillText(nfc.format(total), 75, 77);
    g.fillStyle = "#9aa6d6"; g.font = "11px Ubuntu, 'Segoe UI', sans-serif"; g.fillText("fluxos", 75, 93);
    el("dnl").innerHTML = R.tipos.map(function (o) {
      return '<li><span class="dot" style="background:' + color(o.t) + '"></span>' + o.t + '<span class="n">' + pct(o.fluxos / total) + "</span></li>";
    }).join("");
  }
  function stacked(boxId, lista, labelFn, subFn) {
    var box = el(boxId); if (!lista.length) { box.innerHTML = '<p class="none">Sem dados</p>'; return; }
    var mx = lista[0].tot || 1;
    box.innerHTML = lista.map(function (o) {
      var segs = Object.keys(o.por).sort(function (a, b) { return o.por[b] - o.por[a]; }).map(function (t) {
        return '<i title="' + t + ": " + nf.format(o.por[t]) + '" style="width:' + (o.por[t] / o.tot * 100) + "%;background:" + color(t) + '"></i>';
      }).join("");
      return '<div class="row"><div class="l">' + labelFn(o) + (subFn(o) ? "<small>" + subFn(o) + "</small>" : "") + '</div>' +
        '<div class="tr" style="width:' + (o.tot / mx * 100) + '%">' + segs + '</div><div class="v">' + nfc.format(o.tot) + "</div></div>";
    }).join("");
  }
  function ports() { stacked("ports", R.ports, function (o) { return o.p; }, function (o) { return SERV[o.p] || ""; }); }
  function ips() { stacked("ips", R.ips, function (o) { return o.ip; }, function () { return ""; }); }
  function ia() {
    var box = el("ia"), sub = el("iasub");
    if (!R.ia) { sub.textContent = ""; box.innerHTML = '<p class="none">Sem dados de IA. Gere a amostra e rode com --agregar.</p>'; return; }
    sub.textContent = "Random Forest na amostra de fluxos, acerto geral " + pct(R.ia.acc) + " em fluxos reservados para teste";
    box.innerHTML = R.ia.tipos.map(function (o) {
      return '<div class="row ia"><div class="l">' + o.t + "<small>" + (o.conf && o.rec < 1 ? "confunde com " + o.conf : "n = " + nf.format(o.n)) + "</small></div>" +
        '<div class="tr" title="n = ' + nf.format(o.n) + '"><i style="width:' + o.rec * 100 + "%;background:" + color(o.t) + '"></i></div><div class="v">' + pct(o.rec) + "</div></div>";
    }).join("");
  }

  document.querySelectorAll(".seg button").forEach(function (b) { b.addEventListener("click", function () { setDia(b.getAttribute("data-dia")); }); });
  el("metric").addEventListener("change", function () { st.metric = el("metric").value; drawTL(); });
  el("log").addEventListener("change", function () { st.log = el("log").checked; drawTL(); });
  var timer; window.addEventListener("resize", function () { clearTimeout(timer); timer = setTimeout(drawTL, 120); });
  setDia(D.treino ? "treino" : Object.keys(D)[0]);
})();
</script>
</body>
</html>
"""


def gerar_html():
    if not os.path.exists(AGREGADOS):
        sys.exit(f"{AGREGADOS} nao existe. Rode primeiro: python painel_ddos.py --agregar")
    with open(AGREGADOS, encoding="utf-8") as f:
        dados = json.load(f)
    js = json.dumps(dados, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    html = HTML.replace("__DADOS__", js).replace("__CORES__", json.dumps(COLORS))
    with open(SAIDA, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"gerado: {SAIDA} ({os.path.getsize(SAIDA) / 1e6:.2f} MB)")


if __name__ == "__main__":
    if "--agregar" in sys.argv:
        passo_agregar()
    gerar_html()
