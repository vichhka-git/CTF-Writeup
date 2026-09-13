const $ = s => document.querySelector(s), out = $("#out"), dis = $("#dis"), dot = $("#dot");


function render(el, label, cls, body) {
  el.replaceChildren();                       
  const span = document.createElement("span");
  span.className = cls;
  span.textContent = label;
  el.appendChild(span);
  if (body != null && body !== "") {
    el.appendChild(document.createTextNode("\n" + body));
  }
}

async function go() {
  const b64 = $("#cap").value.trim();
  if (!b64) { out.textContent = "- paste a capsule first -"; return; }
  out.textContent = "thawing...";
  dis.textContent = "";
  try {
    const res = await fetch("/restore", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload: b64 })
    });
    const j = await res.json();
    if (j.ok) {
      dot.classList.add("ok");
      render(out, "Output |", "ok", j.output || "(no output)");
    } else {
      dot.classList.remove("ok");
      render(out, "Rejected |", "err", j.error || "");
    }
    dis.textContent = j.disassembled || "";
  } catch (e) {
    dot.classList.remove("ok");
    dis.textContent = "";
    render(out, "Error |", "err", String(e));
  }
}

$("#go").addEventListener("click", go);
$("#cap").addEventListener("keydown", e => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") go();
});