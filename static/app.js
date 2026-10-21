(function () {
  "use strict";

  var C = 2 * Math.PI * 52; // gauge circumference
  var $ = function (id) { return document.getElementById(id); };
  var form = $("scan-form"), input = $("url"), btn = $("scan-btn");
  var currentReport = null, currentFilter = "All";

  /* ---------- safe DOM helper (never uses innerHTML) ---------- */
  function h(tag, props, kids) {
    var node = document.createElement(tag);
    props = props || {};
    Object.keys(props).forEach(function (k) {
      if (k === "text") node.textContent = props[k];
      else if (k === "class") node.className = props[k];
      else node.setAttribute(k, props[k]);
    });
    (kids || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  /* ---------- storage (wrapped: may be unavailable) ---------- */
  function load(key, fallback) {
    try { var v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; }
    catch (e) { return fallback; }
  }
  function save(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* ignore */ }
  }

  /* ---------- theme ---------- */
  function setTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    $("theme").textContent = t === "dark" ? "Light mode" : "Dark mode";
  }
  var saved = load("theme", null);
  setTheme(saved || (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  $("theme").addEventListener("click", function () {
    var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    setTheme(next); save("theme", next);
  });

  /* ---------- recent scans ---------- */
  function renderRecent() {
    var list = load("recent", []);
    var box = $("recent-list");
    box.textContent = "";
    $("recent").hidden = list.length === 0;
    list.forEach(function (u) {
      var chip = h("button", { "class": "chip", type: "button", text: u.replace(/^https:\/\//, "") });
      chip.addEventListener("click", function () { input.value = u; form.requestSubmit(); });
      box.appendChild(chip);
    });
  }
  function remember(u) {
    var list = load("recent", []).filter(function (x) { return x !== u; });
    list.unshift(u); save("recent", list.slice(0, 5)); renderRecent();
  }
  $("clear-recent").addEventListener("click", function () { save("recent", []); renderRecent(); });

  /* ---------- loading animation ---------- */
  var STEPS = ["Checking the address", "Opening a verified HTTPS connection",
               "Reading the certificate", "Inspecting security headers"];
  var timer = null;
  function startLoading() {
    var ol = $("loading-steps"); ol.textContent = "";
    STEPS.forEach(function (s) { ol.appendChild(h("li", { text: s })); });
    var i = 0;
    function tick() {
      var items = ol.children;
      for (var k = 0; k < items.length; k++)
        items[k].className = k < i ? "done" : (k === i ? "active" : "");
      $("loading-text").textContent = STEPS[Math.min(i, STEPS.length - 1)] + "…";
      if (i < STEPS.length - 1) i++;
    }
    tick(); timer = setInterval(tick, 900);
    $("loading").hidden = false;
  }
  function stopLoading() { clearInterval(timer); $("loading").hidden = true; }

  /* ---------- scanning ---------- */
  function showError(msg) {
    $("error-text").textContent = msg; $("error").hidden = false; $("report").hidden = true;
  }
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var url = input.value.trim();
    input.classList.remove("invalid");
    if (!/^https:\/\//i.test(url)) {
      input.classList.add("invalid");
      showError("Enter an address that starts with https://, for example https://example.com");
      return;
    }
    $("error").hidden = true; $("report").hidden = true;
    btn.disabled = true; btn.textContent = "Scanning…";
    startLoading();
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    }).then(function (r) {
      return r.json().then(function (data) { return { ok: r.ok, data: data }; });
    }).then(function (res) {
      stopLoading();
      if (!res.ok) { showError(res.data.error || "The scan failed."); return; }
      remember(url); renderReport(res.data);
    }).catch(function () {
      stopLoading(); showError("Could not reach the checker. Is the server still running?");
    }).then(function () { btn.disabled = false; btn.textContent = "Scan website"; });
  });

  /* ---------- report ---------- */
  function renderReport(r) {
    currentReport = r; currentFilter = "All";
    $("error").hidden = true;
    $("report-title").textContent = "Report for " + r.url;
    $("report-meta").textContent = "HTTP " + r.http_status + " · scanned " + r.scanned_at +
      (r.final_url && r.final_url !== "https://" + r.url + "/" ? " · final URL " + r.final_url : "");

    var arc = $("gauge-arc");
    arc.setAttribute("class", "gauge-arc " + (r.score >= 80 ? "good" : r.score >= 50 ? "mid" : "low"));
    arc.style.strokeDasharray = "0 " + C;
    $("score").textContent = "0";
    $("report").hidden = false;
    requestAnimationFrame(function () { requestAnimationFrame(function () {
      arc.style.strokeDasharray = (C * r.score / 100) + " " + C;
    }); });
    countUp($("score"), r.score);

    renderCert(r.cert); renderFilters(); renderResults();
    $("report").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function countUp(el, target) {
    var start = null;
    function step(ts) {
      if (start === null) start = ts;
      var p = Math.min((ts - start) / 900, 1);
      el.textContent = Math.round(target * p);
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function renderCert(c) {
    var dl = $("cert"); dl.textContent = "";
    if (!c) { dl.hidden = true; return; }
    [["Issuer", c.issuer], ["Subject", c.subject], ["Valid from", c.valid_from],
     ["Valid until", c.valid_until + " (" + c.days_left + " days left)"],
     ["TLS version", c.tls_version], ["Covers", (c.sans || []).join(", ")]
    ].forEach(function (p) {
      if (!p[1]) return;
      dl.appendChild(h("div", {}, [h("dt", { text: p[0] }), h("dd", { text: p[1] })]));
    });
    dl.hidden = false;
  }

  function renderFilters() {
    var box = $("filters"); box.textContent = "";
    ["All", "Pass", "Warning", "Fail", "Info"].forEach(function (name) {
      var n = name === "All" ? currentReport.results.length
        : currentReport.results.filter(function (x) { return x.status === name; }).length;
      if (name !== "All" && n === 0) return;
      var b = h("button", { "class": "filter", type: "button",
        "aria-pressed": String(name === currentFilter) },
        [document.createTextNode(name), h("span", { "class": "count", text: String(n) })]);
      b.addEventListener("click", function () {
        currentFilter = name; renderFilters(); renderResults();
      });
      box.appendChild(b);
    });
  }

  var uid = 0;
  function renderResults() {
    var ul = $("results"); ul.textContent = "";
    var rows = currentReport.results.filter(function (x) {
      return currentFilter === "All" || x.status === currentFilter;
    });
    if (!rows.length) { ul.appendChild(h("li", { "class": "empty", text: "Nothing to show for this filter." })); return; }
    rows.forEach(function (it) {
      var s = it.status.toLowerCase(), id = "p" + (++uid);
      var head = h("button", { "class": "item-btn", type: "button", "aria-expanded": "false", "aria-controls": id }, [
        h("span", { "class": "chev", text: "▸" }),
        h("span", { "class": "item-name", text: it.name }),
        h("span", { "class": "pill " + s, text: it.status })
      ]);
      var panel = h("div", { "class": "panel", id: id }, [h("p", { text: it.details })]);
      panel.hidden = true;
      if (it.what) {
        panel.appendChild(h("span", { "class": "label", text: "What it does" }));
        panel.appendChild(h("p", { text: it.what }));
      }
      if (it.fix) {
        panel.appendChild(h("span", { "class": "label", text: "How to improve" }));
        panel.appendChild(h("p", { text: it.fix }));
      }
      if (it.example) {
        var copy = h("button", { "class": "copy", type: "button", text: "Copy" });
        copy.addEventListener("click", function () {
          var done = function () { copy.textContent = "Copied"; setTimeout(function () { copy.textContent = "Copy"; }, 1500); };
          if (navigator.clipboard) navigator.clipboard.writeText(it.example).then(done);
        });
        panel.appendChild(h("span", { "class": "label", text: "Example" }));
        panel.appendChild(h("div", { "class": "codebox" }, [h("code", { text: it.example }), copy]));
      }
      head.addEventListener("click", function () {
        var open = head.getAttribute("aria-expanded") === "true";
        head.setAttribute("aria-expanded", String(!open)); panel.hidden = open;
      });
      // Problems start expanded so they are seen first.
      if (s === "warning" || s === "fail") { head.setAttribute("aria-expanded", "true"); panel.hidden = false; }
      ul.appendChild(h("li", { "class": "item " + s }, [head, panel]));
    });
  }

  function setAll(open) {
    document.querySelectorAll(".item-btn").forEach(function (b) {
      b.setAttribute("aria-expanded", String(open));
      $(b.getAttribute("aria-controls")).hidden = !open;
    });
  }
  $("expand").addEventListener("click", function () { setAll(true); });
  $("collapse").addEventListener("click", function () { setAll(false); });

  $("rescan").addEventListener("click", function () {
    input.value = "https://" + currentReport.url; form.requestSubmit();
  });

  /* ---------- CSV download (built in the browser) ---------- */
  function csvCell(v) {
    v = String(v == null ? "" : v);
    if (/^[=+\-@]/.test(v)) v = "'" + v; // block spreadsheet formula injection
    return '"' + v.replace(/"/g, '""') + '"';
  }
  $("csv").addEventListener("click", function () {
    var r = currentReport; if (!r) return;
    var rows = [["Host", r.url], ["Scanned at", r.scanned_at], ["HTTP status", r.http_status],
                ["Score", r.score], [], ["Check", "Status", "Details"]];
    r.results.forEach(function (x) { rows.push([x.name, x.status, x.details]); });
    var text = rows.map(function (row) { return row.map(csvCell).join(","); }).join("\r\n");
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
    a.download = "security-report-" + r.url + ".csv";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });

  renderRecent();
})();
