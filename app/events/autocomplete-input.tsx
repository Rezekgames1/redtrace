"use client";

import { useEffect, useId, useRef, useState } from "react";
import type { InputHTMLAttributes, KeyboardEvent, RefObject } from "react";
import type { Suggestion } from "./suggestions";

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange"> & {
  value: string;
  onChange: (value: string) => void;
  suggestions: Suggestion[];
  inputRef?: RefObject<HTMLInputElement | null>;
  onCaretChange?: (caret: number) => void;
};

export function AutocompleteInput({ value, onChange, suggestions, inputRef, onCaretChange, onKeyDown, onFocus, onBlur, ...props }: Props) {
  const localRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const ref = inputRef ?? localRef;
  const id = useId();
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const visible = open && suggestions.length > 0 && !props.disabled;
  const selected = active < suggestions.length ? active : -1;

  useEffect(() => {
    const list = listRef.current;
    const option = list?.children.item(selected);
    if (!visible || !list || !(option instanceof HTMLElement)) return;
    const top = option.offsetTop - list.offsetTop;
    const bottom = top + option.offsetHeight;
    if (top < list.scrollTop) list.scrollTop = top;
    else if (bottom > list.scrollTop + list.clientHeight) list.scrollTop = bottom - list.clientHeight;
  }, [visible, selected, suggestions]);

  function choose(suggestion: Suggestion) {
    onChange(suggestion.value);
    setOpen(false);
    setActive(-1);
    const caret = suggestion.caret ?? suggestion.value.length;
    onCaretChange?.(caret);
    requestAnimationFrame(() => {
      if (document.activeElement === ref.current && ref.current?.selectionStart === ref.current?.selectionEnd) ref.current?.setSelectionRange(caret, caret);
    });
  }

  function keyDown(event: KeyboardEvent<HTMLInputElement>) {
    if ((event.key === "ArrowDown" || event.key === "ArrowUp") && suggestions.length) {
      event.preventDefault();
      setOpen(true);
      setActive(event.key === "ArrowDown" ? (selected + 1) % suggestions.length : selected <= 0 ? suggestions.length - 1 : selected - 1);
      return;
    }
    if (event.key === "Enter" && visible && selected >= 0) {
      event.preventDefault();
      choose(suggestions[selected]);
      return;
    }
    if (event.key === "Escape" && visible) {
      event.preventDefault();
      event.stopPropagation();
      setOpen(false);
      setActive(-1);
      return;
    }
    onKeyDown?.(event);
  }

  return <div className="suggestionInput">
    <input {...props} ref={ref} value={value} autoComplete="off" role="combobox" aria-autocomplete="list" aria-expanded={visible} aria-controls={visible ? id : undefined} aria-activedescendant={visible && selected >= 0 ? `${id}-${selected}` : undefined}
      onChange={event => { onChange(event.target.value); onCaretChange?.(event.target.selectionStart ?? event.target.value.length); setActive(-1); setOpen(true); }}
      onSelect={event => onCaretChange?.(event.currentTarget.selectionStart ?? value.length)}
      onFocus={event => { setOpen(true); onCaretChange?.(event.target.selectionStart ?? value.length); onFocus?.(event); }}
      onBlur={event => { setOpen(false); setActive(-1); onBlur?.(event); }} onKeyDown={keyDown} />
    {visible && <div className="suggestionPopup"><div className="suggestionHint">↑ ↓ выбрать · Enter вставить · Esc закрыть</div><div id={id} ref={listRef} role="listbox" aria-label={`Подсказки: ${props["aria-label"] ?? "фильтр"}`}>
      {suggestions.map((suggestion, index) => <button key={suggestion.value} id={`${id}-${index}`} type="button" role="option" aria-selected={index === selected} tabIndex={-1} onMouseDown={event => event.preventDefault()} onClick={() => choose(suggestion)}><span>{suggestion.label}</span><small>{suggestion.detail}</small></button>)}
    </div></div>}
  </div>;
}
