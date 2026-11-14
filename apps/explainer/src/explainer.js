// Interactive tour of one purchase. Static: no network, no storage; the page is built only with textContent.
(function () {
  "use strict";
  var stage = document.getElementById("stage");
  var count = document.getElementById("count");
  var dots = document.getElementById("dots");
  var back = document.getElementById("back");
  var next = document.getElementById("next");
  var scenario = "match"; // "match" or "other"
  var i = 0;

  var RULES = [
    ["The buyer's signature is valid", null],
    ["Right network and right gate", null],
    ["The mandate has not expired", null],
    ["This order was not used before", null],
    ["The caller is the buyer or the agent named in the mandate", null],
    ["Right asset", null],
    ["Amount is within the remaining budget", null],
    ["The payee is the shop named in the mandate", "payee"],
    ["The item is the item named in the mandate", null],
  ];

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function add(parent) { for (var k = 1; k < arguments.length; k++) parent.appendChild(arguments[k]); return parent; }
  function card(rows) {
    var dl = el("dl");
    rows.forEach(function (r) { add(dl, el("dt", "", r[0]), el("dd", "", r[1])); });
    return add(el("div", "card"), dl);
  }
  function link(text, href, alt) { var a = el("a", "cta" + (alt ? " alt" : ""), text); a.href = href; return a; }
  function order() {
    return scenario === "match"
      ? [["Shop", "shop.example (as signed)"], ["Item", "report-001"], ["Amount", "1.00 USDC"]]
      : [["Shop", "other-shop.example (not in the mandate)"], ["Item", "report-001"], ["Amount", "1.00 USDC"]];
  }

  var slides = [
    function () {
      var d = el("div", "slide");
      add(d, el("h1", "", "Pay only for what the buyer authorised."),
        el("p", "lede", "A one-minute tour of how a payment is checked by a NEAR contract, and how anyone can prove it afterwards."));
      return d;
    },
    function () {
      var d = el("div", "slide");
      add(d, el("h2", "", "1. The buyer signs a mandate"),
        el("p", "lede", "Before any money moves, the buyer signs what they are willing to pay. It is signed once and cannot be changed afterwards."),
        card([["Buyer", "a person, or an AI agent acting for them"], ["Shop", "shop.example"], ["Item", "report-001"], ["Most they will pay", "1.00 USDC"], ["Valid for", "2 hours"]]));
      return d;
    },
    function () {
      var d = el("div", "slide");
      var f = el("div", "flow");
      function node(t, s, c) { return add(el("div", "node" + (c ? " " + c : "")), el("strong", "", t), el("span", "", s)); }
      add(f, node("Buyer", "pays from another chain"), el("div", "arrow", "→"), node("NEAR Intents", "moves the money"), el("div", "arrow", "→"), node("The gate", "a NEAR contract that holds it", "gate"));
      add(d, el("h2", "", "2. The money waits in the gate"),
        el("p", "lede", "The payment goes to a contract, not straight to the shop. Nobody is paid yet."), f);
      return d;
    },
    function () {
      var d = el("div", "slide");
      var fs = el("fieldset");
      add(fs, el("legend", "", "Choose what arrives:"));
      [["match", "An order that matches the mandate", "Right shop, right item, 1.00 USDC."],
       ["other", "An order that pays a different shop", "Same buyer's money, but a shop the buyer never named."]].forEach(function (o) {
        var lab = el("label", "choice");
        var inp = el("input"); inp.type = "radio"; inp.name = "scenario"; inp.value = o[0]; inp.checked = scenario === o[0];
        inp.addEventListener("change", function () { scenario = o[0]; render(false); });
        var t = el("span"); add(t, el("strong", "", o[1]), el("br"), document.createTextNode(o[2]));
        add(lab, inp, t); add(fs, lab);
      });
      add(d, el("h2", "", "3. An order arrives"), el("p", "lede", "The buyer, or their agent, asks the gate to pay for one order."), fs, card(order()));
      return d;
    },
    function () {
      var d = el("div", "slide");
      var ul = el("ul", "rules");
      RULES.forEach(function (r) {
        var bad = scenario === "other" && r[1] === "payee";
        add(ul, add(el("li", bad ? "fail" : "pass"), el("span", "mark", bad ? "✗ Fails" : "✓ Pass"), el("span", "", r[0])));
      });
      add(d, el("h2", "", "4. The gate checks the rules"),
        el("p", "lede", "Every rule is checked by the contract, in code, and written into the receipt. A model never makes this decision."), ul);
      return d;
    },
    function () {
      var d = el("div", "slide");
      var ok = scenario === "match";
      var v = el("div", "verdict " + (ok ? "pass" : "fail"), ok ? "Released: the shop is paid this exact order, once." : "Refused: nothing is paid.");
      add(v, el("small", "", ok ? "The money goes to the shop named in the mandate, and nowhere else." : "The refusal is recorded. The money stays in the gate and returns to the buyer after the mandate expires."));
      add(d, el("h2", "", "5. Release or refuse"), v);
      return d;
    },
    function () {
      var d = el("div", "slide");
      var ok = scenario === "match";
      var v = el("div", "verdict " + (ok ? "pass" : "fail"), ok ? "Checker: matches what the buyer signed." : "Checker: refused, the shop was not in the mandate.");
      add(v, el("small", "", "Either way, the decision is a receipt anyone can check."));
      add(d, el("h2", "", "6. Anyone can check the receipt"),
        el("p", "lede", "The buyer's finance team opens a static web page, loads the receipt file, and sees the result. No wallet, no account and no server of ours."), v);
      return d;
    },
    function () {
      var d = el("div", "slide");
      var l = el("div", "links");
      add(l, link("Open the receipt checker", "../checker/"), link("Open the test shop", "../shop/", true), link("Back to the home page", "../", true));
      add(d, el("h2", "", "Try it yourself"),
        el("p", "lede", "The receipts on this site are from testnet. The checker reads the chain directly."), l);
      return d;
    },
  ];

  var dotEls = slides.map(function () { var li = el("li"); dots.appendChild(li); return li; });

  function render(animate) {
    stage.textContent = "";
    var s = slides[i]();
    if (animate === false) s.className += " still";
    stage.appendChild(s);
    count.textContent = "Step " + (i + 1) + " of " + slides.length;
    back.disabled = i === 0;
    next.disabled = i === slides.length - 1;
    dotEls.forEach(function (d, k) { if (k === i) d.setAttribute("aria-current", "step"); else d.removeAttribute("aria-current"); });
  }
  function go(d) { var n = i + d; if (n >= 0 && n < slides.length) { i = n; render(); } }
  back.addEventListener("click", function () { go(-1); });
  next.addEventListener("click", function () { go(1); });
  document.addEventListener("keydown", function (e) {
    if (e.target && e.target.tagName === "INPUT") return;
    if (e.key === "ArrowRight") go(1); else if (e.key === "ArrowLeft") go(-1);
  });
  render();
})();
