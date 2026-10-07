/* WebhookGuard security dashboard - frontend logic (task T18).
   Plain browser JavaScript, no framework, no build step.

   All data comes from GET /api/dashboard (the backend reads the existing
   security log). Nothing is hardcoded here; no secrets exist client-side.
   If the backend cannot be reached the banner explains it - no fake data. */

(function () {
  "use strict";

  var POLL_INTERVAL_MS = 10000; // simple polling; the pipeline is request-driven

  var el = {
    status: document.getElementById("conn-status"),
    statusLabel: document.getElementById("conn-label"),
    refresh: document.getElementById("refresh-btn"),
    errorBanner: document.getElementById("error-banner"),
    errorDetail: document.getElementById("error-detail"),
    total: document.getElementById("stat-total"),
    valid: document.getElementById("stat-valid"),
    rejected: document.getElementById("stat-rejected"),
    replayed: document.getElementById("stat-replayed"),
    breakdown: document.getElementById("breakdown"),
    tableBody: document.getElementById("events-body"),
    lastUpdated: document.getElementById("last-updated")
  };

  // Display labels for the contract reason codes (docs/api-contract.md section 4).
  // invalid_signature is shown as "Forged / Tampered": the receiver cannot
  // cryptographically tell the two apart - both fail the HMAC.
  var REASON_LABELS = {
    valid: "Valid",
    invalid_signature: "Forged / Tampered",
    expired: "Expired",
    replayed: "Replayed",
    malformed: "Malformed",
    unknown_key: "Unknown key",
    store_unavailable: "Store error"
  };
  var REASON_ORDER = ["valid", "invalid_signature", "replayed", "expired",
                      "malformed", "unknown_key", "store_unavailable"];

  function fmt(n) { return String(n); }

  function labelFor(reason) {
    return REASON_LABELS[reason] || reason;
  }

  function fmtLogTime(iso) {
    if (!iso) return "-";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    function p(x) { return (x < 10 ? "0" : "") + x; }
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) +
           " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }

  function fmtUnix(ts) {
    if (ts === null || ts === undefined) return "-";
    var d = new Date(Number(ts) * 1000);
    if (isNaN(d.getTime())) return String(ts);
    return fmtLogTime(d.toISOString());
  }

  function setConnection(ok) {
    el.status.classList.remove("online", "offline");
    el.status.classList.add(ok ? "online" : "offline");
    el.statusLabel.textContent = ok ? "Receiver Online" : "Receiver Offline";
  }

  function showError(detail) {
    el.errorBanner.classList.remove("hidden");
    el.errorDetail.textContent = detail || "Check whether the backend is running.";
    setConnection(false);
  }

  function hideError() {
    el.errorBanner.classList.add("hidden");
    setConnection(true);
  }

  /* ---------- rendering ---------- */

  function renderCounts(counts) {
    el.total.textContent = fmt(counts.total);
    el.valid.textContent = fmt(counts.valid);
    el.rejected.textContent = fmt(counts.rejected);
    el.replayed.textContent = fmt(counts.by_reason.replayed || 0);
  }

  function renderBreakdown(byReason, total) {
    el.breakdown.innerHTML = "";
    if (!total) {
      el.breakdown.innerHTML = '<p class="empty-state">No webhook events recorded yet.</p>';
      return;
    }
    // Known reasons first (contract order), then anything unexpected at the end.
    var seen = {};
    var rows = REASON_ORDER.filter(function (r) { return byReason[r] !== undefined; })
                           .map(function (r) { return [r, byReason[r]]; });
    Object.keys(byReason).forEach(function (r) {
      if (!seen.hasOwnProperty(r) && REASON_ORDER.indexOf(r) === -1) {
        rows.push([r, byReason[r]]);
      }
      seen[r] = true;
    });

    rows.forEach(function (pair) {
      var reason = pair[0], count = pair[1];
      var pct = total ? Math.round((count / total) * 100) : 0;

      var row = document.createElement("div");
      row.className = "breakdown-row";

      var lbl = document.createElement("span");
      lbl.className = "breakdown-label";
      lbl.textContent = labelFor(reason);

      var track = document.createElement("div");
      track.className = "breakdown-bar-track";
      var bar = document.createElement("div");
      bar.className = "breakdown-bar bar-" + reason;
      bar.style.width = pct + "%";
      bar.title = count + " of " + total + " (" + pct + "%)";
      track.appendChild(bar);

      var num = document.createElement("span");
      num.className = "breakdown-count";
      num.textContent = fmt(count);

      row.appendChild(lbl);
      row.appendChild(track);
      row.appendChild(num);
      el.breakdown.appendChild(row);
    });
  }

  function statusCell(decision) {
    var td = document.createElement("td");
    var badge = document.createElement("span");
    badge.className = "badge badge-" + (decision === "accepted" ? "accepted" : "rejected");
    badge.textContent = decision === "accepted" ? "Accepted" : "Rejected";
    td.appendChild(badge);
    return td;
  }

  function renderTable(entries) {
    el.tableBody.innerHTML = "";
    if (!entries || !entries.length) {
      var tr = document.createElement("tr");
      var td = document.createElement("td");
      td.colSpan = 6;
      td.className = "empty-state";
      td.textContent = "No webhook events recorded yet.";
      tr.appendChild(td);
      el.tableBody.appendChild(tr);
      return;
    }
    entries.forEach(function (e) {
      var tr = document.createElement("tr");

      tr.appendChild(cellText(fmtLogTime(e.logged_at), "mono"));
      tr.appendChild(cellText(e.event_id || "-", "mono"));
      tr.appendChild(statusCell(e.decision));

      var reasonTd = document.createElement("td");
      reasonTd.className = "reason reason-" + (e.reason || "unknown");
      reasonTd.textContent = labelFor(e.reason);
      tr.appendChild(reasonTd);

      tr.appendChild(cellText(e.key_id || "-", "mono"));
      tr.appendChild(cellText(fmtUnix(e.request_timestamp), "mono"));

      el.tableBody.appendChild(tr);
    });
  }

  function cellText(text, extraClass) {
    var td = document.createElement("td");
    td.className = extraClass || "";
    td.textContent = text;
    return td;
  }

  /* ---------- data loading ---------- */

  function loadData() {
    fetch("/api/dashboard", { headers: { "Accept": "application/json" } })
      .then(function (res) {
        if (!res.ok) {
          // 503 with a JSON error body, or any other non-200
          return res.json().catch(function () { return {}; }).then(function (body) {
            throw new Error(body.message || "HTTP " + res.status);
          });
        }
        return res.json();
      })
      .then(function (data) {
        hideError();
        renderCounts(data.counts);
        renderBreakdown(data.counts.by_reason || {}, data.counts.total);
        renderTable(data.recent);
        el.lastUpdated.textContent = "updated " + fmtLogTime(data.generated_at);
      })
      .catch(function (err) {
        showError("Unable to connect to the security service. Check whether the backend is running. (" +
                  (err && err.message ? err.message : "network error") + ")");
        // Leave previous numbers visible but grey them out? Keep simple: show banner only.
      });
  }

  el.refresh.addEventListener("click", loadData);

  // Simple 10 s polling - no WebSockets/SSE needed for a request-driven pipeline.
  loadData();
  setInterval(loadData, POLL_INTERVAL_MS);
})();
