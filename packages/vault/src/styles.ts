export const VAULT_STYLES = `@layer clearance-vault {
  .cv-root {
    --cv-accent: #3155d9;
    --cv-bg: #f7f8fb;
    --cv-panel: #fff;
    --cv-text: #151a2d;
    --cv-muted: #5d6478;
    --cv-border: #dce0eb;
    --cv-danger: #b42318;
    color: var(--cv-text);
    background: var(--cv-bg);
    font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    min-height: 100%;
  }
  .cv-root * { box-sizing: border-box; }
  .cv-skip { position: absolute; left: -10000px; }
  .cv-skip:focus { left: 1rem; top: 1rem; z-index: 10; background: var(--cv-panel); padding: .65rem 1rem; }
  .cv-layout { display: grid; grid-template-columns: minmax(13rem, 18rem) minmax(0, 1fr); min-height: 100%; }
  .cv-sidebar { padding: 1.25rem; border-right: 1px solid var(--cv-border); background: var(--cv-panel); }
  .cv-brand { font-size: 1.1rem; font-weight: 750; margin: 0 0 1.25rem; }
  .cv-nav { display: grid; gap: .25rem; }
  .cv-nav button { appearance: none; border: 0; border-radius: .5rem; background: transparent; color: inherit; cursor: pointer; font: inherit; padding: .65rem .75rem; text-align: left; }
  .cv-nav button:hover { background: #eef1f8; }
  .cv-nav button[aria-current="page"] { background: color-mix(in srgb, var(--cv-accent) 12%, white); color: var(--cv-accent); font-weight: 700; }
  .cv-main { width: min(100%, 64rem); padding: clamp(1rem, 4vw, 3rem); }
  .cv-main:focus { outline: none; }
  .cv-header { margin-bottom: 1.5rem; }
  .cv-header h1 { font-size: clamp(1.55rem, 3vw, 2.1rem); line-height: 1.2; margin: 0 0 .4rem; }
  .cv-muted { color: var(--cv-muted); margin: 0; }
  .cv-grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(min(100%, 19rem), 1fr)); }
  .cv-card { background: var(--cv-panel); border: 1px solid var(--cv-border); border-radius: .8rem; padding: 1.15rem; }
  .cv-card:focus { outline: 3px solid color-mix(in srgb, var(--cv-accent) 45%, white); outline-offset: 2px; }
  .cv-card h2 { font-size: 1.05rem; margin: 0 0 .8rem; }
  .cv-form { display: grid; gap: .85rem; max-width: 30rem; }
  .cv-field { display: grid; gap: .3rem; }
  .cv-field label { font-weight: 650; }
  .cv-field input, .cv-field select { border: 1px solid #adb5c7; border-radius: .45rem; color: inherit; font: inherit; min-height: 2.65rem; padding: .55rem .65rem; width: 100%; }
  .cv-actions { align-items: center; display: flex; flex-wrap: wrap; gap: .6rem; margin-top: .25rem; }
  .cv-button { appearance: none; background: var(--cv-accent); border: 1px solid var(--cv-accent); border-radius: .45rem; color: white; cursor: pointer; font: inherit; font-weight: 700; min-height: 2.55rem; padding: .55rem .85rem; }
  .cv-button-secondary { background: var(--cv-panel); color: var(--cv-accent); }
  .cv-button-danger { background: var(--cv-panel); border-color: var(--cv-danger); color: var(--cv-danger); }
  .cv-button:disabled { cursor: wait; opacity: .55; }
  .cv-list { display: grid; gap: .6rem; list-style: none; margin: 0; padding: 0; }
  .cv-list-item { align-items: center; border: 1px solid var(--cv-border); border-radius: .55rem; display: flex; flex-wrap: wrap; gap: .7rem; justify-content: space-between; padding: .75rem; }
  .cv-status { min-height: 1.5rem; margin: 1rem 0; }
  .cv-error { color: var(--cv-danger); font-weight: 650; }
  .cv-secret { overflow-wrap: anywhere; background: #111827; border-radius: .45rem; color: #fff; font: 14px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; padding: .8rem; user-select: all; }
  .cv-modal { align-items: center; background: rgb(21 26 45 / .45); display: flex; inset: 0; justify-content: center; padding: 1rem; position: fixed; z-index: 20; }
  .cv-confirm { border-left: .25rem solid var(--cv-danger); max-width: 32rem; padding-left: .85rem; width: min(100%, 32rem); }
  @media (max-width: 46rem) {
    .cv-layout { grid-template-columns: 1fr; }
    .cv-sidebar { border-bottom: 1px solid var(--cv-border); border-right: 0; }
    .cv-nav { display: flex; overflow-x: auto; padding-bottom: .25rem; }
    .cv-nav button { flex: 0 0 auto; }
  }
  @media (prefers-reduced-motion: no-preference) {
    .cv-nav button, .cv-button { transition: background-color .15s ease, color .15s ease, border-color .15s ease; }
  }
}`;
