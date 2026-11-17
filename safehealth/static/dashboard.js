// Live refresh of the security dashboard. Uses textContent only - never innerHTML - so alert
// text that contains attacker-controlled strings (usernames, paths) cannot inject markup.
(function () {
  "use strict";
  var tiles = document.getElementById("tiles");
  var body = document.getElementById("alerts");
  var live = document.getElementById("live");
  if (!tiles || !body) { return; }
  var csrf = body.getAttribute("data-csrf");

  function cell(text) { var td = document.createElement("td"); td.textContent = text; return td; }

  function render(data) {
    tiles.replaceChildren();
    Object.keys(data.counts).forEach(function (label) {
      var div = document.createElement("div");
      div.className = "tile" + (label.indexOf("High") !== -1 && data.counts[label] ? " hot" : "");
      var num = document.createElement("span");
      num.className = "num";
      num.textContent = data.counts[label];
      div.appendChild(num);
      div.appendChild(document.createTextNode(label));
      tiles.appendChild(div);
    });
    body.replaceChildren();
    data.alerts.forEach(function (a) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(a.time));
      var sev = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "sev " + (["High", "Medium", "Low"].indexOf(a.severity) !== -1 ? a.severity : "");
      badge.textContent = a.severity;
      sev.appendChild(badge);
      tr.appendChild(sev);
      [a.rule, a.summary, a.response, a.hits].forEach(function (t) { tr.appendChild(cell(t)); });
      var status = document.createElement("td");
      if (a.status === "open") {
        var form = document.createElement("form");
        form.method = "post";
        form.action = "/security/alerts/" + encodeURIComponent(a.id) + "/ack";
        form.className = "inline";
        var token = document.createElement("input");
        token.type = "hidden"; token.name = "csrf_token"; token.value = csrf;
        var button = document.createElement("button");
        button.className = "btn small"; button.type = "submit"; button.textContent = "Acknowledge";
        form.appendChild(token); form.appendChild(button); status.appendChild(form);
      } else {
        status.textContent = "ack by " + a.ack_by;
      }
      tr.appendChild(status);
      body.appendChild(tr);
    });
    if (!data.alerts.length) {
      var tr = document.createElement("tr"); var td = cell("No alerts."); td.colSpan = 7; td.className = "empty";
      tr.appendChild(td); body.appendChild(tr);
    }
  }

  function poll() {
    fetch("/security/api/summary", { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok || r.redirected) { throw new Error("signed out"); } return r.json(); })
      .then(function (data) { render(data); live.textContent = "live - updated " + new Date().toLocaleTimeString(); })
      .catch(function () { live.textContent = "not updating (session ended?) - reload the page"; });
  }
  setInterval(poll, 5000);
})();
