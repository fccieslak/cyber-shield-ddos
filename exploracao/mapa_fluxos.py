#!/usr/bin/env python3
"""Mapa 2D dos fluxos do CIC-DDoS2019 + features mais importantes (Random Forest).

Uso (com o venv ativo):
    source ~/venv-ddos/bin/activate
    cd ~/ddos-dados && python mapa_fluxos.py            # t-SNE (mais bonito, mais lento)
    cd ~/ddos-dados && python mapa_fluxos.py --rapido   # PCA (segundos)

Entrada : <BASE>/amostra_fluxos.csv   (gerado por: python gerador_fluxos.py --amostrar)
Saidas  : <BASE>/mapa_fluxos.html, <BASE>/mapa_treino.png, <BASE>/mapa_teste.png
"""
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.manifold import TSNE
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

BASE = os.environ.get("DDOS_BASE", os.path.expanduser("~/ddos-dados"))
ENTRADA = os.path.join(BASE, "amostra_fluxos.csv")
SAIDA_HTML = os.path.join(BASE, "mapa_fluxos.html")

N_MAPA = 600          # fluxos por tipo desenhados no mapa
SEMENTE = 42
# Sem IPs, timestamp e porta de origem, para o modelo nao decorar identificadores.
FEATURES = [
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
FALLBACK = ["#f9a8d4", "#a5b4fc", "#fcd34d", "#6ee7b7", "#fda4af"]


def cor(t):
    if t in COLORS:
        return COLORS[t]
    return FALLBACK[sum(map(ord, t)) % len(FALLBACK)]


def carregar():
    if not os.path.exists(ENTRADA):
        sys.exit(f"{ENTRADA} nao existe. Rode antes: python gerador_fluxos.py --amostrar")
    df = pd.read_csv(ENTRADA)
    df.columns = [c.strip() for c in df.columns]
    faltando = [c for c in ["dia", "tipo"] + FEATURES if c not in df.columns]
    if faltando:
        sys.exit(f"Colunas ausentes: {faltando}. Rode de novo: python gerador_fluxos.py --amostrar")
    df[FEATURES] = df[FEATURES].apply(pd.to_numeric, errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan)
    return df


def processar(df, dia, rapido):
    d = df[df["dia"] == dia].reset_index(drop=True)
    if d.empty:
        return None
    print(f"[{dia}] {len(d)} fluxos, {d['tipo'].nunique()} tipos", flush=True)
    X = d[FEATURES].copy()
    X = X.fillna(X.median(numeric_only=True)).fillna(0)
    y = d["tipo"].astype(str).to_numpy(dtype=object)

    # --- Random Forest: importancia das features e acerto em fluxos reservados
    cont = pd.Series(y).value_counts()
    estrat = y if (cont >= 2).all() else None
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=SEMENTE, stratify=estrat)
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced",
                                n_jobs=2, random_state=SEMENTE)
    rf.fit(Xtr, ytr)
    pred = rf.predict(Xte)
    acc = float(accuracy_score(yte, pred))
    f1 = float(f1_score(yte, pred, average="macro", zero_division=0))
    imp = sorted(zip(FEATURES, rf.feature_importances_), key=lambda p: -p[1])
    print(f"[{dia}] acerto {acc:.3f}, F1 macro {f1:.3f}", flush=True)

    # --- Amostra equilibrada para o mapa
    partes = [g.sample(min(len(g), N_MAPA), random_state=SEMENTE) for _, g in d.groupby("tipo")]
    m = pd.concat(partes).reset_index(drop=True)
    Xm = m[FEATURES].copy()
    Xm = Xm.fillna(X.median(numeric_only=True)).fillna(0)
    Z = StandardScaler().fit_transform(np.log1p(Xm.clip(lower=0)))
    if rapido or len(m) < 50:
        emb = PCA(n_components=2, random_state=SEMENTE).fit_transform(Z)
    else:
        print(f"[{dia}] t-SNE em {len(m)} pontos (pode levar alguns minutos)...", flush=True)
        perp = float(min(30, max(5, (len(m) - 1) / 4)))
        emb = TSNE(n_components=2, perplexity=perp, init="pca", random_state=SEMENTE).fit_transform(Z)
    emb = (emb - emb.min(axis=0)) / np.maximum(emb.max(axis=0) - emb.min(axis=0), 1e-9)

    tipos = [{"t": t, "n": int(cont[t]), "m": int((m["tipo"] == t).sum())}
             for t in cont.index]
    tipos.sort(key=lambda o: ((o["t"] != "BENIGN"), -o["n"]))
    ordem = {o["t"]: i for i, o in enumerate(tipos)}
    top = [f for f, _ in imp[:4]]
    pts = []
    for i in range(len(m)):
        linha = [round(float(emb[i, 0]), 4), round(float(emb[i, 1]), 4), ordem[m.at[i, "tipo"]]]
        linha += [None if pd.isna(m.at[i, f]) else round(float(m.at[i, f]), 2) for f in top]
        pts.append(linha)
    return {
        "tipos": tipos, "pts": pts, "top": top,
        "imp": [{"f": f, "v": round(float(v), 4)} for f, v in imp[:10]],
        "acc": round(acc, 4), "f1": round(f1, 4), "nmapa": N_MAPA,
        "_emb": emb, "_m": m, "_imp": imp,
    }


def png(res, dia):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 5.4), gridspec_kw={"width_ratios": [1.5, 1]})
    fig.patch.set_facecolor("#070a1f")
    for a in (a1, a2):
        a.set_facecolor("#0d1233")
        for s in a.spines.values():
            s.set_color("#2a3270")
        a.tick_params(colors="#9aa6d6")
    emb, m = res["_emb"], res["_m"]
    for o in res["tipos"]:
        sel = (m["tipo"] == o["t"]).values
        a1.scatter(emb[sel, 0], emb[sel, 1], s=9, color=cor(o["t"]), alpha=0.8, linewidths=0,
                   label=f"{o['t']} ({o['n']})")
    a1.set_xticks([]); a1.set_yticks([])
    a1.set_title(f"Mapa dos fluxos ({dia}): um ponto por fluxo", color="#e8ecff", fontsize=12)
    leg = a1.legend(facecolor="#0d1233", edgecolor="#2a3270", labelcolor="#e8ecff", fontsize=9,
                    markerscale=2.2, loc="best")
    top = res["_imp"][:10][::-1]
    a2.barh([f for f, _ in top], [v for _, v in top], color="#7aa2ff")
    a2.set_title("Features mais importantes (Random Forest)", color="#e8ecff", fontsize=12)
    a2.set_xlabel("importância", color="#9aa6d6")
    fig.tight_layout()
    caminho = os.path.join(BASE, f"mapa_{dia}.png")
    fig.savefig(caminho, dpi=130, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"gerado: {caminho}")


HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mapa de fluxos, CIC-DDoS2019</title>
<style>
  :root { --bg:#070a1f; --ink:#e8ecff; --soft:#9aa6d6; --line:rgba(140,160,255,0.18); --panel:rgba(10,14,40,0.72); --accent:#7aa2ff; }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body { color: var(--ink); font-family: "Ubuntu","Segoe UI",system-ui,sans-serif; font-size: 0.9rem;
    background: radial-gradient(ellipse 70% 60% at 12% 10%, rgba(38,66,190,0.45) 0%, transparent 60%),
                radial-gradient(ellipse 60% 60% at 90% 90%, rgba(118,40,190,0.4) 0%, transparent 62%), var(--bg);
    background-attachment: fixed; }
  #app { display: grid; grid-template-rows: auto minmax(0,1fr); height: 100%; padding: 20px 24px 20px; gap: 16px; }
  header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; }
  h1 { margin: 0; font-size: 1.5rem; font-weight: 300; }
  h2 { margin: 0 0 12px; font-size: 0.95rem; font-weight: 500; }
  .sub { margin: 5px 0 0; color: var(--soft); font-size: 0.85rem; }
  .seg { display: inline-flex; border: 1px solid var(--line); border-radius: 999px; background: var(--panel); padding: 3px; }
  .seg button { font: inherit; color: var(--soft); background: transparent; border: 0; padding: 6px 15px; border-radius: 999px; cursor: pointer; }
  .seg button[aria-pressed="true"] { color: #fff; background: rgba(122,162,255,0.28); }
  button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .main { display: grid; grid-template-columns: minmax(0,1.7fr) minmax(0,1fr); gap: 16px; min-height: 0; }
  .box { border: 1px solid var(--line); border-radius: 12px; background: var(--panel); padding: 14px 16px; min-height: 0; min-width: 0; display: flex; flex-direction: column; }
  #chips { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }
  .chip { display: inline-flex; align-items: center; gap: 7px; font: inherit; color: var(--ink); background: transparent;
          border: 1px solid var(--line); border-radius: 999px; padding: 4px 11px; cursor: pointer; }
  .chip[aria-pressed="false"] { opacity: 0.35; }
  .chip small { color: var(--soft); }
  .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  .cwrap { position: relative; flex: 1; min-height: 0; }
  canvas { position: absolute; inset: 0; width: 100%; height: 100%; }
  #tip { position: absolute; display: none; pointer-events: none; z-index: 5; padding: 8px 10px; border: 1px solid var(--line);
         border-radius: 8px; background: rgba(8,12,36,0.94); font-size: 0.8rem; line-height: 1.5; font-variant-numeric: tabular-nums; }
  .row { display: grid; grid-template-columns: 1fr 46px; gap: 10px; align-items: center; margin-bottom: 10px; }
  .row .lab { font-size: 0.82rem; margin-bottom: 4px; }
  .row .bar { height: 7px; border-radius: 4px; background: var(--accent); box-shadow: 0 0 8px var(--accent); }
  .row .v { text-align: right; color: var(--soft); font-size: 0.82rem; font-variant-numeric: tabular-nums; }
  @media (max-width: 900px) { html, body { height: auto; } #app { height: auto; } .main { grid-template-columns: 1fr; } .cwrap { height: 60vh; flex: none; } }
</style>
</head>
<body>
<div id="app">
  <header>
    <div><h1>Mapa de fluxos</h1><p class="sub" id="sub"></p></div>
    <div class="seg" role="group" aria-label="Conjunto de dados">
      <button type="button" data-dia="treino" aria-pressed="true">Treino (01-12)</button>
      <button type="button" data-dia="teste" aria-pressed="false">Teste (03-11)</button>
    </div>
  </header>
  <div class="main">
    <div class="box"><div id="chips" role="group" aria-label="Tipos de tráfego"></div>
      <div class="cwrap"><canvas id="c" aria-label="Mapa 2D dos fluxos, colorido por tipo"></canvas><div id="tip"></div></div></div>
    <div class="box"><h2>Features mais importantes</h2><div id="imp"></div></div>
  </div>
</div>
<script id="dados" type="application/json">__DADOS__</script>
<script>
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("dados").textContent);
  var COLORS = __CORES__, FALLBACK = ["#f9a8d4", "#a5b4fc", "#fcd34d", "#6ee7b7", "#fda4af"];
  var nf = new Intl.NumberFormat("pt-BR"), nfc = new Intl.NumberFormat("pt-BR", { notation: "compact", maximumFractionDigits: 2 });
  function color(t) { if (COLORS[t]) return COLORS[t]; var h = 0; for (var i = 0; i < t.length; i++) h += t.charCodeAt(i); return FALLBACK[h % FALLBACK.length]; }
  function el(id) { return document.getElementById(id); }
  var dia = "treino", on = {}, R = null, cv = el("c"), tip = el("tip"), px = [];

  function setDia(d) {
    dia = d; R = D[d]; on = {};
    R.tipos.forEach(function (o) { on[o.t] = true; });
    document.querySelectorAll(".seg button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-dia") === d)); });
    el("sub").textContent = "Cada ponto é um fluxo (até " + R.nmapa + " por tipo). Random Forest: " +
      (R.acc * 100).toFixed(1).replace(".", ",") + "% de acerto em fluxos reservados para teste.";
    chips(); bars(); draw();
  }
  function chips() {
    var box = el("chips"); box.innerHTML = "";
    R.tipos.forEach(function (o) {
      var b = document.createElement("button"); b.type = "button"; b.className = "chip";
      b.setAttribute("aria-pressed", String(on[o.t]));
      b.innerHTML = '<span class="dot" style="background:' + color(o.t) + '"></span>' + o.t + ' <small>' + nf.format(o.n) + '</small>';
      b.addEventListener("click", function () { on[o.t] = !on[o.t]; chips(); draw(); });
      b.addEventListener("dblclick", function () { R.tipos.forEach(function (x) { on[x.t] = x.t === o.t; }); chips(); draw(); });
      box.appendChild(b);
    });
  }
  function bars() {
    var box = el("imp"); box.innerHTML = ""; var mx = R.imp[0].v || 1;
    R.imp.forEach(function (o) {
      var r = document.createElement("div"); r.className = "row";
      r.innerHTML = '<div><div class="lab">' + o.f + '</div><div class="bar" style="width:' + (o.v / mx * 100) + '%"></div></div>' +
        '<div class="v">' + (o.v * 100).toFixed(1).replace(".", ",") + '%</div>';
      box.appendChild(r);
    });
  }
  function draw() {
    var w = cv.clientWidth, h = cv.clientHeight, dpr = Math.min(window.devicePixelRatio || 1, 2);
    cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    var g = cv.getContext("2d"); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
    var pad = 14; px = [];
    R.pts.forEach(function (p) {
      var t = R.tipos[p[2]].t; if (!on[t]) return;
      var x = pad + p[0] * (w - 2 * pad), y = pad + p[1] * (h - 2 * pad);
      px.push([x, y, p]);
      g.fillStyle = color(t); g.globalAlpha = 0.78;
      g.beginPath(); g.arc(x, y, 3, 0, 6.2832); g.fill();
    });
    g.globalAlpha = 1;
  }
  cv.addEventListener("mousemove", function (e) {
    var b = cv.getBoundingClientRect(), mx = e.clientX - b.left, my = e.clientY - b.top, best = null, bd = 100;
    px.forEach(function (q) { var d = (q[0] - mx) * (q[0] - mx) + (q[1] - my) * (q[1] - my); if (d < bd) { bd = d; best = q; } });
    if (!best) { tip.style.display = "none"; return; }
    var p = best[2], html = '<b><span class="dot" style="background:' + color(R.tipos[p[2]].t) + '"></span> ' + R.tipos[p[2]].t + "</b>";
    R.top.forEach(function (f, i) { html += "<br>" + f + ": " + (p[3 + i] === null ? "sem dado" : nfc.format(p[3 + i])); });
    tip.innerHTML = html; tip.style.display = "block";
    tip.style.left = Math.min(mx + 14, b.width - 220) + "px"; tip.style.top = Math.min(my + 14, b.height - 120) + "px";
  });
  cv.addEventListener("mouseleave", function () { tip.style.display = "none"; });
  document.querySelectorAll(".seg button").forEach(function (b) { b.addEventListener("click", function () { setDia(b.getAttribute("data-dia")); }); });
  var timer; window.addEventListener("resize", function () { clearTimeout(timer); timer = setTimeout(draw, 120); });
  setDia(D.treino ? "treino" : Object.keys(D)[0]);
})();
</script>
</body>
</html>
"""


def main():
    rapido = "--rapido" in sys.argv
    df = carregar()
    saida = {}
    for dia in ("treino", "teste"):
        res = processar(df, dia, rapido)
        if res is None:
            continue
        png(res, dia)
        saida[dia] = {k: v for k, v in res.items() if not k.startswith("_")}
    if not saida:
        sys.exit("Nenhum dado nos conjuntos treino/teste.")
    js = json.dumps(saida, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    html = HTML.replace("__DADOS__", js).replace("__CORES__", json.dumps(COLORS))
    with open(SAIDA_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"gerado: {SAIDA_HTML} ({os.path.getsize(SAIDA_HTML) / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
