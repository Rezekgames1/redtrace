import assert from "node:assert/strict";

export async function checkPreferences({ command, evaluate, wait }) {
  const key = "redtrace.event-preferences.v1";
  const original = await evaluate(`localStorage.getItem(${JSON.stringify(key)})`);
  const name = `GUI preference check ${process.pid}-${Date.now()}`;
  const typeInto = async (selector, text) => {
    await evaluate(`document.querySelector(${JSON.stringify(selector)}).focus(); document.querySelector(${JSON.stringify(selector)}).select()`);
    await command("Input.insertText", { text });
  };
  const panel = async (label) => {
    await evaluate(`Array.from(document.querySelectorAll('.preferencesActions button')).find(button => button.textContent.startsWith(${JSON.stringify(label)})).click()`);
    await wait(150);
  };
  const fields = () => evaluate("Array.from(document.querySelectorAll('.eventHead .columnHeading')).map(element => element.dataset.field)");
  try {
    for (let attempt = 0; attempt < 80; attempt++) {
      if (await evaluate("document.querySelectorAll('.eventRow').length > 0")) break;
      await wait(250);
    }
    await panel("Колонки");
    await evaluate("Array.from(document.querySelectorAll('.eventPreferences button')).find(button => button.textContent === 'Стандартные колонки').click()");
    await wait(150);
    await evaluate("document.querySelector('button[aria-label=\"Убрать user.name\"]').click()");
    await evaluate("document.querySelector('button[data-add-column=\"process.pid\"]').click()");
    await wait(150);
    await evaluate("document.querySelector('button[aria-label=\"Сдвинуть process.pid влево\"]').click()");
    await wait(150);
    const columns = await fields();
    assert.deepEqual(columns, ["@timestamp", "level", "source", "event.id", "process.pid", "event.description"]);
    assert.equal(await evaluate("document.querySelector('button[aria-label=\"Убрать event.description\"]').disabled"), true);
    await panel("Колонки");
    const source = await evaluate("document.querySelector('.eventRow .sourceCell').textContent");
    await typeInto(".queryInput input", source);
    await evaluate("document.querySelector('.runButton').click()");
    await wait(1000);
    await typeInto(".queryInput input", "unexecuted draft should not be saved");
    await panel("Представления");
    await typeInto("input[aria-label=\"Название представления\"]", name);
    await evaluate("document.querySelector('.viewSave button[type=submit]').click()");
    await wait(150);
    const saved = await evaluate(`JSON.parse(localStorage.getItem(${JSON.stringify(key)})).views.find(view => view.name === ${JSON.stringify(name)})`);
    assert.ok(saved, "view was not persisted");
    assert.equal(saved.query, source);
    assert.equal(saved.mode, "contains");
    assert.deepEqual(saved.columns, columns);
    await command("Page.reload");
    await wait(2500);
    assert.deepEqual(await fields(), columns, "column settings did not survive reload");
    await panel("Представления");
    await evaluate(`Array.from(document.querySelectorAll('.savedView')).find(row => row.dataset.viewId === ${JSON.stringify(saved.id)}).querySelector('button').click()`);
    await wait(1000);
    assert.equal(await evaluate("document.querySelector('.queryInput input').value"), source);
    assert.equal(await evaluate("document.querySelector('select[aria-label=\"Режим поиска\"]').value"), "contains");
    assert.deepEqual(await fields(), columns);
    assert.ok(await evaluate("document.querySelectorAll('.eventRow').length > 0"));
    await panel("Представления");
    await evaluate(`document.querySelector('button[aria-label=' + ${JSON.stringify(JSON.stringify(`Изменить ${name}`))} + ']').click()`);
    const renamed = `${name} updated`;
    await typeInto("input[aria-label=\"Название представления\"]", renamed);
    await evaluate("document.querySelector('.viewSave button[type=submit]').click()");
    await wait(150);
    assert.equal(await evaluate(`JSON.parse(localStorage.getItem(${JSON.stringify(key)})).views.find(view => view.id === ${JSON.stringify(saved.id)}).name`), renamed);
    await evaluate(`document.querySelector('button[aria-label=' + ${JSON.stringify(JSON.stringify(`Удалить ${renamed}`))} + ']').click()`);
    await wait(150);
    assert.equal(await evaluate(`JSON.parse(localStorage.getItem(${JSON.stringify(key)})).views.some(view => view.id === ${JSON.stringify(saved.id)})`), false);
    console.log("PASS: actual GUI column add/remove/reorder, mandatory description, saved executed query, reload persistence, apply/rename/delete view");
  } finally {
    await evaluate(`(() => { const value=${JSON.stringify(original)}; if(value===null) localStorage.removeItem(${JSON.stringify(key)}); else localStorage.setItem(${JSON.stringify(key)},value); window.dispatchEvent(new StorageEvent('storage',{key:${JSON.stringify(key)},newValue:value})); })()`);
    await evaluate("if(document.querySelector('.eventPreferences')) Array.from(document.querySelectorAll('.preferencesActions button')).find(button => button.getAttribute('aria-expanded')==='true')?.click()");
  }
}
