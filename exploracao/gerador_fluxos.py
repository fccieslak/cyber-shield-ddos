#!/usr/bin/env python3
"""Visao por fluxos (estilo CICFlowMeter) do CIC-DDoS2019.

Passo 1 (so uma vez, precisa do duckdb do venv):
    source ~/venv-ddos/bin/activate
    cd ~/ddos-dados && python gerador_fluxos.py --amostrar

Passo 2 (gera o HTML; usa so a biblioteca padrao):
    cd ~/ddos-dados && python3 gerador_fluxos.py

Entrada : <BASE>/treino/*.csv e <BASE>/teste/*.csv  (so no passo 1)
Saida   : <BASE>/amostra_fluxos.csv  e  <BASE>/visual_fluxos.html
"""
import csv
import glob
import json
import math
import os
import sys

BASE = os.environ.get("DDOS_BASE", os.path.expanduser("~/ddos-dados"))
AMOSTRA = os.path.join(BASE, "amostra_fluxos.csv")
SAIDA = os.path.join(BASE, "visual_fluxos.html")

N_ATAQUE = 1500   # fluxos de ataque sorteados por arquivo
N_BENIGN = 1500   # fluxos BENIGN por arquivo (os primeiros, ou todos se houver menos)

TEXTO = ["Timestamp", "Source IP", "Destination IP"]
NUM = [
    "Source Port", "Destination Port", "Protocol", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Average Packet Size",
    "SYN Flag Count", "ACK Flag Count",
]


# --------------------------------------------------------------------------
# Passo 1: amostragem com DuckDB
# --------------------------------------------------------------------------
def amostrar():
    import duckdb

    con = duckdb.connect()
    con.sql("SET memory_limit='1GB'; SET threads=2;")
    esquema = ["dia VARCHAR", "tipo VARCHAR"]
    esquema += [f'"{c}" VARCHAR' for c in TEXTO]
    esquema += [f'"{c}" DOUBLE' for c in NUM]
    con.sql("DROP TABLE IF EXISTS amostra")
    con.sql("CREATE TABLE amostra (" + ", ".join(esquema) + ")")

    for dia in ("treino", "teste"):
        for arq in sorted(glob.glob(os.path.join(BASE, dia, "*.csv"))):
            print(f"processando {dia}/{os.path.basename(arq)} ...", flush=True)
            leitura = f"read_csv_auto('{arq}', header=true, ignore_errors=true)"
            cols = [r[0] for r in con.sql(f"DESCRIBE SELECT * FROM {leitura}").fetchall()]
            mapa = {c.strip(): c for c in cols}
            if "Label" not in mapa:
                sys.exit(f"Coluna Label nao encontrada em {arq}")
            partes = [f"'{dia}' AS dia", f'TRIM("{mapa["Label"]}") AS tipo']
            for c in TEXTO:
                partes.append(f'CAST("{mapa[c]}" AS VARCHAR) AS "{c}"' if c in mapa
                              else f'NULL AS "{c}"')
            for c in NUM:
                partes.append(f'TRY_CAST("{mapa[c]}" AS DOUBLE) AS "{c}"' if c in mapa
                              else f'NULL AS "{c}"')
            fonte = f"(SELECT {', '.join(partes)} FROM {leitura})"
            for filtro, clausula in [
                ("tipo = 'BENIGN'", f"LIMIT {N_BENIGN}"),
                ("tipo <> 'BENIGN'", f"USING SAMPLE {N_ATAQUE} ROWS"),
            ]:
                # o filtro vai num subselect: USING SAMPLE age antes do WHERE
                con.sql(f"INSERT INTO amostra BY NAME "
                        f"SELECT * FROM (SELECT * FROM {fonte} WHERE {filtro}) {clausula}")

    con.sql(f"""
        COPY (
            SELECT dia, regexp_replace(tipo, '^DrDoS_', '') AS tipo,
                   * EXCLUDE (dia, tipo)
            FROM amostra
        ) TO '{AMOSTRA}' (HEADER, DELIMITER ',')
    """)
    con.sql("SELECT dia, regexp_replace(tipo, '^DrDoS_', '') AS tipo, COUNT(*) AS total "
            "FROM amostra GROUP BY ALL ORDER BY dia, tipo").show()
    print(f"{AMOSTRA} gerado")


# --------------------------------------------------------------------------
# Passo 2: HTML
# --------------------------------------------------------------------------
def numero(txt):
    try:
        v = float(txt)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(v):
        return None
    return int(v) if v == int(v) and abs(v) < 1e15 else round(v, 3)


def texto(txt, corte=None):
    t = (txt or "").strip()
    if t.lower() in ("", "null", "none", "nan"):
        return None
    return t[:corte] if corte else t


def ler_dados():
    if not os.path.exists(AMOSTRA):
        sys.exit(f"{AMOSTRA} nao existe. Rode primeiro: python gerador_fluxos.py --amostrar")
    linhas = []
    with open(AMOSTRA, newline="", encoding="utf-8") as f:
        leitor = csv.DictReader(f)
        leitor.fieldnames = [c.strip() for c in leitor.fieldnames]
        esperadas = ["dia", "tipo"] + TEXTO + NUM
        faltando = [c for c in esperadas if c not in leitor.fieldnames]
        if faltando:
            sys.exit(f"Colunas ausentes: {faltando}. Rode de novo com --amostrar.")
        for r in leitor:
            linha = [r["dia"].strip(), r["tipo"].strip()]
            linha += [texto(r["Timestamp"], 19), texto(r["Source IP"]), texto(r["Destination IP"])]
            linha += [numero(r[c]) for c in NUM]
            linhas.append(linha)
    return {"cols": ["dia", "tipo"] + TEXTO + NUM, "rows": linhas}


HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fluxos de rede, CIC-DDoS2019</title>
<style>
  :root {
    --bg: #070a1f; --ink: #e8ecff; --soft: #9aa6d6; --line: rgba(140,160,255,0.18);
    --panel: rgba(10,14,40,0.72); --accent: #7aa2ff;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    color: var(--ink);
    font-family: "Ubuntu", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", sans-serif;
    font-size: 0.9rem;
    background:
      radial-gradient(ellipse 70% 60% at 12% 10%, rgba(38,66,190,0.5) 0%, transparent 60%),
      radial-gradient(ellipse 60% 60% at 90% 85%, rgba(118,40,190,0.45) 0%, transparent 62%),
      var(--bg);
    background-attachment: fixed;
  }
  #app { display: grid; grid-template-rows: auto auto auto minmax(0,1fr) auto; height: 100%;
         padding: 18px 22px 12px; gap: 14px; }
  header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; }
  h1 { margin: 0; font-size: 1.5rem; font-weight: 300; }
  h2 { margin: 0 0 8px; font-size: 0.95rem; font-weight: 500; }
  .sub { margin: 4px 0 0; color: var(--soft); font-size: 0.85rem; }
  .seg { display: inline-flex; border: 1px solid var(--line); border-radius: 999px; background: var(--panel); padding: 3px; }
  .seg button { font: inherit; color: var(--soft); background: transparent; border: 0; padding: 6px 15px; border-radius: 999px; cursor: pointer; }
  .seg button[aria-pressed="true"] { color: #fff; background: rgba(122,162,255,0.28); box-shadow: 0 0 14px rgba(122,162,255,0.35); }
  button:focus-visible, select:focus-visible, input:focus-visible, tr:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .filters { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  #chips { display: flex; gap: 6px; flex-wrap: wrap; }
  .chip { display: inline-flex; align-items: center; gap: 7px; font: inherit; color: var(--ink);
          background: var(--panel); border: 1px solid var(--line); border-radius: 999px; padding: 5px 11px; cursor: pointer; }
  .chip[aria-pressed="false"] { opacity: 0.38; }
  .chip small { color: var(--soft); font-variant-numeric: tabular-nums; }
  .dot { width: 9px; height: 9px; border-radius: 50%; flex: none; display: inline-block; }
  input[type="search"], select { font: inherit; color: var(--ink); background: rgba(20,26,70,0.9);
          border: 1px solid var(--line); border-radius: 8px; padding: 6px 10px; }
  input[type="search"] { width: 190px; }
  .tag { font: inherit; color: var(--ink); background: rgba(122,162,255,0.2); border: 1px solid var(--line);
         border-radius: 999px; padding: 4px 10px; cursor: pointer; }
  .charts { display: grid; grid-template-columns: minmax(0,2.2fr) minmax(0,1fr) minmax(0,1fr); gap: 14px; }
  .box { border: 1px solid var(--line); border-radius: 10px; background: var(--panel); padding: 12px 14px; min-width: 0; }
  .distbox { position: relative; }
  #dist { width: 100%; height: 190px; display: block; }
  #tip { position: absolute; display: none; pointer-events: none; z-index: 5; padding: 7px 10px; border: 1px solid var(--line);
         border-radius: 8px; background: rgba(8,12,36,0.94); font-size: 0.78rem; line-height: 1.5; font-variant-numeric: tabular-nums; }
  .bars { list-style: none; margin: 0; padding: 0; }
  .bars li { display: grid; grid-template-columns: 1fr 52px; gap: 8px; align-items: center; margin-bottom: 6px;
             cursor: pointer; border-radius: 6px; padding: 2px 4px; }
  .bars li:hover, .bars li:focus-visible { background: rgba(122,162,255,0.12); }
  .bars .lab { display: flex; justify-content: space-between; gap: 8px; font-size: 0.8rem; margin-bottom: 3px;
               font-variant-numeric: tabular-nums; overflow: hidden; white-space: nowrap; }
  .bars .bar { height: 5px; border-radius: 3px; }
  .bars .n { text-align: right; color: var(--soft); font-size: 0.8rem; font-variant-numeric: tabular-nums; }
  .tablewrap { display: grid; grid-template-columns: minmax(0,1fr) 300px; gap: 14px; min-height: 0; }
  .tscroll { overflow: auto; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); min-height: 0; }
  table { border-collapse: collapse; width: 100%; font-size: 0.8rem; font-variant-numeric: tabular-nums; }
  th { position: sticky; top: 0; background: #11173f; text-align: left; font-weight: 500; padding: 8px 10px;
       white-space: nowrap; cursor: pointer; color: var(--soft); border-bottom: 1px solid var(--line); }
  th[aria-sort] { color: var(--ink); }
  td { padding: 6px 10px; white-space: nowrap; border-bottom: 1px solid rgba(140,160,255,0.07); }
  td.r, th.r { text-align: right; }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: rgba(122,162,255,0.1); }
  tbody tr.sel { background: rgba(122,162,255,0.22); }
  #detail { overflow: auto; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); padding: 12px 14px; min-height: 0; }
  #detail dl { margin: 0; display: grid; grid-template-columns: 1fr auto; gap: 5px 10px; font-size: 0.8rem; }
  #detail dt { color: var(--soft); }
  #detail dd { margin: 0; text-align: right; font-variant-numeric: tabular-nums; word-break: break-all; }
  .empty { color: var(--soft); margin: 0; }
  .pager { display: flex; align-items: center; gap: 10px; color: var(--soft); font-size: 0.82rem; }
  .pager button { font: inherit; color: var(--ink); background: var(--panel); border: 1px solid var(--line);
                  border-radius: 8px; padding: 4px 12px; cursor: pointer; }
  .pager button:disabled { opacity: 0.35; cursor: default; }
  @media (max-width: 1000px) {
    html, body { height: auto; }
    #app { height: auto; }
    .charts, .tablewrap { grid-template-columns: 1fr; }
    .tscroll { max-height: 60vh; }
  }
</style>
</head>
<body>
<div id="app">
  <header>
    <div>
      <h1>Fluxos de rede</h1>
      <p class="sub" id="sub"></p>
    </div>
    <div class="seg" role="group" aria-label="Conjunto de dados">
      <button type="button" data-dia="treino" aria-pressed="true">Treino (01-12)</button>
      <button type="button" data-dia="teste" aria-pressed="false">Teste (03-11)</button>
    </div>
  </header>

  <div class="filters">
    <div id="chips" role="group" aria-label="Tipos de tráfego"></div>
    <input id="q" type="search" placeholder="Buscar IP ou porta" aria-label="Buscar IP ou porta">
    <span id="tags"></span>
  </div>

  <section class="charts">
    <div class="box distbox">
      <select id="feat" aria-label="Atributo"></select>
      <canvas id="dist"></canvas>
      <div id="tip"></div>
    </div>
    <div class="box"><h2>Portas de destino</h2><ul class="bars" id="ports"></ul></div>
    <div class="box"><h2>IPs de origem</h2><ul class="bars" id="ips"></ul></div>
  </section>

  <section class="tablewrap">
    <div class="tscroll"><table id="tbl"><thead></thead><tbody></tbody></table></div>
    <aside id="detail"><p class="empty">Selecione um fluxo na tabela.</p></aside>
  </section>

  <div class="pager">
    <button type="button" id="prev">Anterior</button>
    <button type="button" id="next">Próxima</button>
    <span id="pinfo"></span>
  </div>
</div>

<script id="dados" type="application/json">__DADOS__</script>
<script>
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("dados").textContent);
  var idx = {};
  D.cols.forEach(function (c, i) { idx[c] = i; });
  var I = { dia: idx["dia"], tipo: idx["tipo"], sip: idx["Source IP"], dip: idx["Destination IP"],
            sp: idx["Source Port"], dp: idx["Destination Port"], proto: idx["Protocol"] };

  var FEATS = ["Flow Duration", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Average Packet Size"];
  var COLS = [
    { k: "Timestamp", l: "Início" }, { k: "_src", l: "Origem" }, { k: "_dst", l: "Destino" },
    { k: "Protocol", l: "Proto" }, { k: "Flow Duration", l: "Duração (µs)", r: 1 },
    { k: "Total Fwd Packets", l: "Pkts fwd", r: 1 }, { k: "Total Backward Packets", l: "Pkts bwd", r: 1 },
    { k: "Flow Bytes/s", l: "Bytes/s", r: 1 }, { k: "Flow Packets/s", l: "Pkts/s", r: 1 }, { k: "tipo", l: "Tipo" }
  ];
  var COLORS = { BENIGN: "#e6f0ff", Syn: "#ff4d6d", UDP: "#ffb454", UDPLag: "#ffe066", LDAP: "#b388ff",
    MSSQL: "#4fc3ff", NetBIOS: "#ff7a59", Portmap: "#4ade80", DNS: "#38bdf8", NTP: "#f472b6",
    SNMP: "#c4b5fd", SSDP: "#fb923c", TFTP: "#2dd4bf" };
  var FALLBACK = ["#f9a8d4", "#a5b4fc", "#fcd34d", "#6ee7b7", "#fda4af"];
  var PROTO = { 1: "ICMP", 6: "TCP", 17: "UDP" };
  var PAGE = 100;

  var nf = new Intl.NumberFormat("pt-BR");
  var nfc = new Intl.NumberFormat("pt-BR", { notation: "compact", maximumFractionDigits: 2 });
  function color(t) {
    if (COLORS[t]) return COLORS[t];
    var h = 0; for (var i = 0; i < t.length; i++) h = (h * 31 + t.charCodeAt(i)) >>> 0;
    return FALLBACK[h % FALLBACK.length];
  }
  function rgba(hex, a) {
    var n = parseInt(hex.slice(1), 16);
    return "rgba(" + (n >> 16) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
  }
  function lg(v) { return Math.log10(1 + Math.max(v, 0)); }
  function fmt(v) { return v === null || v === undefined ? "–" : (typeof v === "number" ? nf.format(v) : v); }
  function el(id) { return document.getElementById(id); }

  var st = { dia: "treino", tipos: {}, feat: FEATS[0], q: "", port: null, ip: null,
             sort: "Timestamp", dir: 1, page: 0, sel: null };
  var dayRows = [], tiposDia = [], view = [];

  function cellValue(r, k) {
    if (k === "_src") return (r[I.sip] || "") + ":" + String(r[I.sp] === null ? 0 : r[I.sp]).padStart(5, "0");
    if (k === "_dst") return (r[I.dip] || "") + ":" + String(r[I.dp] === null ? 0 : r[I.dp]).padStart(5, "0");
    return r[idx[k]];
  }

  function loadDay() {
    dayRows = D.rows.filter(function (r) { return r[I.dia] === st.dia; });
    var m = {};
    dayRows.forEach(function (r) { m[r[I.tipo]] = (m[r[I.tipo]] || 0) + 1; });
    tiposDia = Object.keys(m).map(function (t) { return { t: t, n: m[t] }; });
    tiposDia.sort(function (a, b) { return ((b.t === "BENIGN") - (a.t === "BENIGN")) || (b.n - a.n); });
    st.tipos = {}; tiposDia.forEach(function (o) { st.tipos[o.t] = true; });
    st.port = null; st.ip = null; st.q = ""; el("q").value = ""; st.sel = null;
  }

  function applyFilter() {
    var q = st.q.trim().toLowerCase();
    view = dayRows.filter(function (r) {
      if (!st.tipos[r[I.tipo]]) return false;
      if (st.port !== null && r[I.dp] !== st.port) return false;
      if (st.ip !== null && r[I.sip] !== st.ip) return false;
      if (q) {
        var s = ((r[I.sip] || "") + " " + r[I.sp] + " " + (r[I.dip] || "") + " " + r[I.dp]).toLowerCase();
        if (s.indexOf(q) < 0) return false;
      }
      return true;
    });
    sortView(); st.page = 0;
  }
  function sortView() {
    var k = st.sort, d = st.dir;
    view.sort(function (a, b) {
      var x = cellValue(a, k), y = cellValue(b, k);
      if (x === null || x === undefined) return 1;
      if (y === null || y === undefined) return -1;
      return (x < y ? -1 : x > y ? 1 : 0) * d;
    });
  }

  function renderChips() {
    var box = el("chips"); box.innerHTML = "";
    tiposDia.forEach(function (o) {
      var b = document.createElement("button");
      b.type = "button"; b.className = "chip";
      b.setAttribute("aria-pressed", String(!!st.tipos[o.t]));
      b.innerHTML = '<span class="dot" style="background:' + color(o.t) + ';box-shadow:0 0 7px ' + color(o.t) + '"></span>' +
        o.t + ' <small>' + nf.format(o.n) + '</small>';
      b.addEventListener("click", function () { st.tipos[o.t] = !st.tipos[o.t]; refresh(); });
      b.addEventListener("dblclick", function () {
        tiposDia.forEach(function (x) { st.tipos[x.t] = x.t === o.t; }); refresh();
      });
      box.appendChild(b);
    });
    var tags = el("tags"); tags.innerHTML = "";
    [["port", "Porta "], ["ip", "IP "]].forEach(function (p) {
      if (st[p[0]] === null) return;
      var b = document.createElement("button");
      b.type = "button"; b.className = "tag"; b.textContent = p[1] + st[p[0]] + " ✕";
      b.addEventListener("click", function () { st[p[0]] = null; refresh(); });
      tags.appendChild(b);
    });
  }

  function topList(ulId, keyFn, onPick, labelFn) {
    var m = {};
    view.forEach(function (r) {
      var k = keyFn(r); if (k === null || k === undefined) return;
      var o = m[k] || (m[k] = { k: k, n: 0, t: {} });
      o.n++; o.t[r[I.tipo]] = (o.t[r[I.tipo]] || 0) + 1;
    });
    var arr = Object.keys(m).map(function (k) { return m[k]; })
      .sort(function (a, b) { return b.n - a.n; }).slice(0, 7);
    var ul = el(ulId); ul.innerHTML = "";
    var mx = arr.length ? arr[0].n : 1;
    arr.forEach(function (o) {
      var dom = Object.keys(o.t).sort(function (a, b) { return o.t[b] - o.t[a]; })[0];
      var li = document.createElement("li"); li.tabIndex = 0;
      li.innerHTML = '<div><div class="lab"><span>' + labelFn(o.k) + '</span></div>' +
        '<div class="bar" style="width:' + (o.n / mx * 100) + '%;background:' + color(dom) + ';box-shadow:0 0 6px ' + color(dom) + '"></div></div>' +
        '<div class="n">' + nf.format(o.n) + '</div>';
      function pick() { onPick(o.k); }
      li.addEventListener("click", pick);
      li.addEventListener("keydown", function (e) { if (e.key === "Enter") pick(); });
      ul.appendChild(li);
    });
    if (!arr.length) ul.innerHTML = '<li><span class="n">sem dados</span></li>';
  }

  var distCv = el("dist"), distInfo = null;
  function drawDist() {
    var g = distCv.getContext("2d");
    var w = distCv.clientWidth, h = distCv.clientHeight, dpr = Math.min(window.devicePixelRatio || 1, 2);
    distCv.width = Math.round(w * dpr); distCv.height = Math.round(h * dpr);
    g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
    var ai = idx[st.feat], groups = {}, lo = Infinity, hi = -Infinity;
    view.forEach(function (r) {
      var v = r[ai]; if (v === null) return;
      var l = lg(v); (groups[r[I.tipo]] || (groups[r[I.tipo]] = [])).push(l);
      if (l < lo) lo = l; if (l > hi) hi = l;
    });
    var names = Object.keys(groups);
    g.font = "11px Ubuntu, 'Segoe UI', sans-serif";
    if (!names.length) { distInfo = null; g.fillStyle = "#9aa6d6"; g.fillText("Sem dados para os filtros atuais", 50, 40); return; }
    if (hi - lo < 1e-9) hi = lo + 1;
    var NB = 36, L = 40, R = 8, T = 34, B = 24, pw = w - L - R, ph = h - T - B;
    var props = {}, ymax = 0;
    names.forEach(function (t) {
      var a = new Array(NB).fill(0);
      groups[t].forEach(function (l) { a[Math.min(NB - 1, Math.floor((l - lo) / (hi - lo) * NB))]++; });
      props[t] = a.map(function (c) { return c / groups[t].length; });
      props[t].forEach(function (p) { if (p > ymax) ymax = p; });
    });
    distInfo = { lo: lo, hi: hi, NB: NB, names: names, props: props, L: L, pw: pw };
    g.strokeStyle = "rgba(140,160,255,0.12)"; g.fillStyle = "#9aa6d6"; g.textAlign = "right"; g.lineWidth = 1;
    [0, 0.5, 1].forEach(function (f) {
      var y = T + ph - ph * f;
      g.beginPath(); g.moveTo(L, y); g.lineTo(L + pw, y); g.stroke();
      g.fillText(Math.round(ymax * f * 100) + "%", L - 6, y + 4);
    });
    g.textAlign = "center";
    for (var k = Math.ceil(lo); k <= Math.floor(hi); k++) {
      var x = L + (k - lo) / (hi - lo) * pw;
      g.fillText(nfc.format(Math.pow(10, k)), x, h - 7);
    }
    names.forEach(function (t) {
      var c = color(t);
      g.beginPath();
      props[t].forEach(function (p, i) {
        var x = L + (i + 0.5) / NB * pw, y = T + ph - p / ymax * ph;
        if (i === 0) g.moveTo(x, y); else g.lineTo(x, y);
      });
      g.strokeStyle = c; g.lineWidth = 1.8; g.stroke();
      g.lineTo(L + (NB - 0.5) / NB * pw, T + ph); g.lineTo(L + 0.5 / NB * pw, T + ph); g.closePath();
      g.fillStyle = rgba(c, 0.14); g.fill();
    });
  }
  var tip = el("tip");
  distCv.addEventListener("mousemove", function (e) {
    if (!distInfo) return;
    var b = distCv.getBoundingClientRect(), x = e.clientX - b.left;
    var i = Math.floor((x - distInfo.L) / distInfo.pw * distInfo.NB);
    if (i < 0 || i >= distInfo.NB) { tip.style.display = "none"; return; }
    var a = distInfo.lo + i / distInfo.NB * (distInfo.hi - distInfo.lo);
    var z = distInfo.lo + (i + 1) / distInfo.NB * (distInfo.hi - distInfo.lo);
    var html = "<b>" + nfc.format(Math.pow(10, a) - 1) + " a " + nfc.format(Math.pow(10, z) - 1) + "</b>";
    distInfo.names.forEach(function (t) {
      html += '<br><span class="dot" style="background:' + color(t) + '"></span> ' + t + ": " +
        (distInfo.props[t][i] * 100).toFixed(1).replace(".", ",") + "%";
    });
    tip.innerHTML = html; tip.style.display = "block";
    var left = x + 16; if (left > b.width - 190) left = x - 190;
    tip.style.left = left + "px"; tip.style.top = "36px";
  });
  distCv.addEventListener("mouseleave", function () { tip.style.display = "none"; });

  function renderHead() {
    var tr = document.createElement("tr");
    COLS.forEach(function (c) {
      var th = document.createElement("th");
      th.className = c.r ? "r" : ""; th.tabIndex = 0;
      th.textContent = c.l + (st.sort === c.k ? (st.dir > 0 ? " ▲" : " ▼") : "");
      if (st.sort === c.k) th.setAttribute("aria-sort", st.dir > 0 ? "ascending" : "descending");
      function go() {
        if (st.sort === c.k) st.dir = -st.dir; else { st.sort = c.k; st.dir = 1; }
        sortView(); st.page = 0; renderHead(); renderTable(); renderPager();
      }
      th.addEventListener("click", go);
      th.addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
      tr.appendChild(th);
    });
    var head = el("tbl").tHead; head.innerHTML = ""; head.appendChild(tr);
  }
  function cellText(r, c) {
    switch (c.k) {
      case "_src": return (r[I.sip] || "–") + ":" + fmt(r[I.sp]).replace(/\./g, "");
      case "_dst": return (r[I.dip] || "–") + ":" + fmt(r[I.dp]).replace(/\./g, "");
      case "Protocol": var p = r[I.proto]; return p === null ? "–" : (PROTO[p] || p);
      case "tipo": return '<span class="dot" style="background:' + color(r[I.tipo]) + '"></span> ' + r[I.tipo];
      case "Flow Bytes/s": case "Flow Packets/s": var v = r[idx[c.k]]; return v === null ? "–" : nfc.format(v);
      default: return fmt(r[idx[c.k]]);
    }
  }
  function renderTable() {
    var body = el("tbl").tBodies[0], start = st.page * PAGE, html = [];
    for (var i = start; i < Math.min(view.length, start + PAGE); i++) {
      var r = view[i];
      html.push('<tr tabindex="0" data-i="' + i + '"' + (st.sel === r ? ' class="sel"' : "") + ">" +
        COLS.map(function (c) { return '<td class="' + (c.r ? "r" : "") + '">' + cellText(r, c) + "</td>"; }).join("") + "</tr>");
    }
    body.innerHTML = html.join("");
  }
  el("tbl").tBodies[0].addEventListener("click", function (e) { pick(e.target); });
  el("tbl").tBodies[0].addEventListener("keydown", function (e) { if (e.key === "Enter") pick(e.target); });
  function pick(t) {
    var tr = t.closest("tr"); if (!tr) return;
    st.sel = view[+tr.getAttribute("data-i")];
    document.querySelectorAll("tbody tr.sel").forEach(function (x) { x.classList.remove("sel"); });
    tr.classList.add("sel"); renderDetail();
  }
  function renderDetail() {
    var box = el("detail");
    if (!st.sel) { box.innerHTML = '<p class="empty">Selecione um fluxo na tabela.</p>'; return; }
    var html = "<h2>Fluxo selecionado</h2><dl>";
    D.cols.forEach(function (c, i) {
      if (c === "dia") return;
      var v = st.sel[i];
      if (c === "tipo") v = '<span class="dot" style="background:' + color(v) + '"></span> ' + v;
      else if (c === "Protocol" && v !== null) v = PROTO[v] ? PROTO[v] + " (" + v + ")" : v;
      else if (c === "Source Port" || c === "Destination Port") v = v === null ? "–" : String(v);
      else v = fmt(v);
      html += "<dt>" + c + "</dt><dd>" + v + "</dd>";
    });
    box.innerHTML = html + "</dl>";
  }
  function renderPager() {
    var pages = Math.max(1, Math.ceil(view.length / PAGE));
    el("prev").disabled = st.page <= 0; el("next").disabled = st.page >= pages - 1;
    var a = view.length ? st.page * PAGE + 1 : 0, b = Math.min(view.length, (st.page + 1) * PAGE);
    el("pinfo").textContent = nf.format(a) + " a " + nf.format(b) + " de " + nf.format(view.length) + " fluxos";
  }
  el("prev").addEventListener("click", function () { st.page--; renderTable(); renderPager(); });
  el("next").addEventListener("click", function () { st.page++; renderTable(); renderPager(); });

  function refresh() {
    applyFilter();
    renderChips();
    topList("ports", function (r) { return r[I.dp]; }, function (k) { st.port = k; refresh(); }, function (k) { return nf.format(k).replace(/\./g, ""); });
    topList("ips", function (r) { return r[I.sip]; }, function (k) { st.ip = k; refresh(); }, function (k) { return k; });
    drawDist(); renderHead(); renderTable(); renderPager(); renderDetail();
    el("sub").textContent = "CIC-DDoS2019, conjunto de " + st.dia + ": " + nf.format(view.length) +
      " de " + nf.format(dayRows.length) + " fluxos amostrados";
  }

  FEATS.forEach(function (f) { var o = document.createElement("option"); o.value = f; o.textContent = f; el("feat").appendChild(o); });
  el("feat").addEventListener("change", function () { st.feat = el("feat").value; drawDist(); });
  el("q").addEventListener("input", function () { st.q = el("q").value; refresh(); });
  document.querySelectorAll(".seg button").forEach(function (b) {
    b.addEventListener("click", function () {
      st.dia = b.getAttribute("data-dia");
      document.querySelectorAll(".seg button").forEach(function (x) {
        x.setAttribute("aria-pressed", String(x === b));
      });
      loadDay(); refresh();
    });
  });
  var timer;
  window.addEventListener("resize", function () { clearTimeout(timer); timer = setTimeout(drawDist, 120); });

  loadDay(); refresh();
})();
</script>
</body>
</html>
"""


def gerar_html():
    dados = ler_dados()
    if not dados["rows"]:
        sys.exit("A amostra esta vazia.")
    js = json.dumps(dados, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    with open(SAIDA, "w", encoding="utf-8") as f:
        f.write(HTML.replace("__DADOS__", js))
    print(f"{len(dados['rows'])} fluxos embutidos")
    print(f"gerado: {SAIDA} ({os.path.getsize(SAIDA) / 1e6:.1f} MB)")


if __name__ == "__main__":
    if "--amostrar" in sys.argv:
        amostrar()
    gerar_html()
