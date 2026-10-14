import assert from "node:assert/strict";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the event explorer shell", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /RED\/\/TRACE|RED<span[^>]*>\{"\/\/"\}<\/span>TRACE/i);
  assert.match(html, /Журнал событий/);
  assert.match(html, /aria-label="Поисковый запрос"/);
  assert.match(html, /Событий не найдено|ПОТОК СОБЫТИЙ/);
  assert.doesNotMatch(html, /SkeletonPreview|react-loading-skeleton/);
  assert.doesNotMatch(html, /Обновить логи|Сохранить представление|Аналитика/);
  assert.match(html, /Приостановить ленту/);
  assert.doesNotMatch(html, /class="histogramPanel"/);
});
