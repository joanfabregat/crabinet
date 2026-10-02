// Rule tests for crabinet-frontend-html-sink. Run with:
// semgrep scan --test --config .semgrep/ .semgrep/

export function sinks(element: HTMLElement, frame: HTMLIFrameElement, html: string) {
  // ruleid: crabinet-frontend-html-sink
  element.innerHTML = html;
  // ruleid: crabinet-frontend-html-sink
  element.outerHTML = html;
  // ruleid: crabinet-frontend-html-sink
  element.innerHTML += html;
  // ruleid: crabinet-frontend-html-sink
  element.insertAdjacentHTML("beforeend", html);
  // ruleid: crabinet-frontend-html-sink
  frame.srcdoc = html;
  // ruleid: crabinet-frontend-html-sink
  frame.setAttribute("srcdoc", html);
  // ruleid: crabinet-frontend-html-sink
  document.write(html);
  // ruleid: crabinet-frontend-html-sink
  window.open("https://example.com/");
  // ruleid: crabinet-frontend-html-sink
  open("https://example.com/");
  // ruleid: crabinet-frontend-html-sink
  const compiled = new Function("return 1");
  // ruleid: crabinet-frontend-html-sink
  eval(html);
  // ruleid: crabinet-frontend-html-sink
  setTimeout("alert(1)", 10);
  // ruleid: crabinet-frontend-html-sink
  window.setTimeout(`alert(${html})`, 10);
  // ruleid: crabinet-frontend-html-sink
  window.setInterval("tick()" + html, 10);
  return compiled;
}

export function Unsafe({ html }: { html: string }) {
  return (
    <div>
      {/* ruleid: crabinet-frontend-html-sink */}
      <section dangerouslySetInnerHTML={{ __html: html }} />
      {/* ruleid: crabinet-frontend-html-sink */}
      <iframe srcdoc={html} sandbox="" />
      {/* ruleid: crabinet-frontend-html-sink */}
      <iframe srcDoc={html} sandbox="" />
    </div>
  );
}

export function safe(element: HTMLElement, text: string, xhr: XMLHttpRequest) {
  // ok: crabinet-frontend-html-sink
  element.textContent = text;
  // ok: crabinet-frontend-html-sink
  const read = element.innerHTML;
  // ok: crabinet-frontend-html-sink
  window.setTimeout(() => element.focus(), 0);
  // ok: crabinet-frontend-html-sink
  const timer = setTimeout(() => undefined, 10);
  // ok: crabinet-frontend-html-sink
  window.setTimeout(() => element.querySelector<HTMLElement>("button")?.focus(), 0);
  // ok: crabinet-frontend-html-sink
  xhr.open("POST", "/api/v1/upload", true);
  clearTimeout(timer);
  return read;
}

export function Safe({ text }: { text: string }) {
  // ok: crabinet-frontend-html-sink
  return <p title={text}>{text}</p>;
}
