<script lang="ts">
  // The guided form of one third-party page: what the page shows, where the browser goes back, the buttons, the
  // server-to-server callback (with an optional HMAC signature), the answers that carry the page URL and the
  // automatic outcomes. The checks are the server's (internal/mock/pages.go), done here first.
  import Button from '../Button.svelte';
  import Field from '../Field.svelte';
  import { t, tk } from '../../lib/i18n/index.svelte';
  import { cleanPage, pageProblems, parseList, parseSet, parseValues, setText, valuesText, type PageCallback, type PageFrom, type PageLink, type ThirdPartyPage } from '../../lib/api';

  interface Props {
    page: ThirdPartyPage;
    /** The other pages of the group (unique ids). */
    others: ThirdPartyPage[];
    /** The page has a stored HMAC key (an empty key keeps it). */
    keyStored: boolean;
    busy?: boolean;
    error?: string;
    onsave: (p: ThirdPartyPage) => void;
    oncancel: () => void;
  }
  let { page, others, keyStored, busy = false, error, onsave, oncancel }: Props = $props();
  const uid = $props.id();

  // svelte-ignore state_referenced_locally
  let p = $state<ThirdPartyPage>(structuredClone($state.snapshot(page)) as ThirdPartyPage);
  const problems = $derived(pageProblems(cleanPage(p), others, keyStored));
  const actions = $derived(p.buttons.map((b) => b.action).filter(Boolean));
  const fieldErr = (field: string) => {
    const l = problems.filter((x) => x.field === field);
    return l.length ? l.map((x) => tk(`pg.err.${x.code}`, { item: x.item ?? '' }, x.code)).join(' ') : undefined;
  };

  function newCallback(): PageCallback {
    return { method: 'POST', url: '', headers: { 'Content-Type': 'application/json' }, body: '{"ref":"{ref}","outcome":"{action}"}', body_type: 'json' };
  }
  function toggleCallback(on: boolean): void {
    if (on) p.callback = newCallback();
    else delete p.callback;
  }
  function toggleHmac(on: boolean): void {
    if (!p.callback) return;
    if (on) p.callback.hmac = { header: 'X-Signature', key: '', algorithm: 'sha256', encoding: 'hex', prefix: '' };
    else delete p.callback.hmac;
  }
  const headerRows = $derived(Object.entries(p.callback?.headers ?? {}));
  function setHeader(oldKey: string, key: string, value: string): void {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(p.callback!.headers ?? {})) out[k === oldKey ? key : k] = k === oldKey ? value : v;
    p.callback!.headers = out;
  }
  function dropHeader(key: string): void {
    const out = { ...(p.callback!.headers ?? {}) };
    delete out[key];
    p.callback!.headers = out;
  }
  function setReturnFrom(l: PageLink, kind: string): void {
    if (!kind) delete l.return_from;
    else if (kind === 'req.body') l.return_from = { from: 'req.body', path: l.return_from?.path || '$.returnUrl' };
    else l.return_from = { from: kind as PageFrom['from'], name: l.return_from?.name || 'returnUrl' };
  }
  function setReturnWhere(l: PageLink, v: string): void {
    if (!l.return_from) return;
    if (l.return_from.from === 'req.body') l.return_from = { from: 'req.body', path: v };
    else l.return_from = { from: l.return_from.from, name: v };
  }
  const autoRows = $derived(Object.entries(p.auto ?? {}));
  function setAuto(oldKey: string, key: string, action: string): void {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(p.auto ?? {})) out[k === oldKey ? key : k] = k === oldKey ? action : v;
    if (!(oldKey in (p.auto ?? {}))) out[key] = action;
    p.auto = out;
  }
  function dropAuto(key: string): void {
    const out = { ...(p.auto ?? {}) };
    delete out[key];
    p.auto = out;
  }
</script>

<form class="pform stack-sm" data-testid="page-form" onsubmit={(ev) => { ev.preventDefault(); if (!problems.length) onsave(cleanPage(p)); }}>
  <fieldset>
    <legend>{t('pg.f.what')}</legend>
    <div class="grid2">
      <Field label={t('pg.f.id')} hint={t('pg.f.idHint')} error={fieldErr('id')}>
        {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" bind:value={p.id} maxlength="63" spellcheck="false" autocomplete="off" placeholder="pay" />{/snippet}
      </Field>
      <Field label={t('pg.f.title')} hint={t('pg.f.titleHint')} error={fieldErr('title')}>
        {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} bind:value={p.title} maxlength="120" placeholder={t('pg.f.titlePh')} />{/snippet}
      </Field>
    </div>
    <Field label={t('pg.f.description')} hint={t('pg.f.descriptionHint')} error={fieldErr('description')}>
      {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} value={p.description ?? ''} maxlength="1000" oninput={(ev) => (p.description = ev.currentTarget.value)} />{/snippet}
    </Field>
    <div class="grid2">
      <Field label={t('pg.f.ref')} hint={t('pg.f.refHint')} error={fieldErr('ref')}>
        {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" value={p.ref ?? ''} spellcheck="false" placeholder={'{query.paymentId}'} oninput={(ev) => (p.ref = ev.currentTarget.value)} />{/snippet}
      </Field>
      <Field label={t('pg.f.show')} hint={t('pg.f.showHint')} error={fieldErr('show')}>
        {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" value={(p.show ?? []).join(', ')} spellcheck="false" placeholder="amount, order" onchange={(ev) => (p.show = parseList(ev.currentTarget.value))} />{/snippet}
      </Field>
    </div>
  </fieldset>

  <fieldset>
    <legend>{t('pg.f.return')}</legend>
    <Field label={t('pg.f.returnUrl')} hint={t('pg.f.returnUrlHint')} error={fieldErr('return_url')}>
      {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" value={p.return_url ?? ''} spellcheck="false" placeholder={'https://app.test/pay/return?ref={ref}&outcome={action}'} oninput={(ev) => (p.return_url = ev.currentTarget.value)} />{/snippet}
    </Field>
    <Field label={t('pg.f.returnHosts')} hint={t('pg.f.returnHostsHint')} error={fieldErr('return_hosts')}>
      {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" value={(p.return_hosts ?? []).join(', ')} spellcheck="false" placeholder="app.test, shop.test" onchange={(ev) => (p.return_hosts = parseList(ev.currentTarget.value))} />{/snippet}
    </Field>
  </fieldset>

  <fieldset>
    <legend>{t('pg.f.buttons')}</legend>
    <p class="subtle">{t('pg.f.buttonsHint')}</p>
    {#each p.buttons as b, i (i)}
      <div class="rowline">
        <input aria-label={t('pg.f.action', { n: i + 1 })} class="mono" bind:value={b.action} maxlength="32" spellcheck="false" placeholder="approve" />
        <input aria-label={t('pg.f.label', { n: i + 1 })} bind:value={b.label} maxlength="60" placeholder={t('pg.f.labelPh')} />
        <input aria-label={t('pg.f.values', { n: i + 1 })} class="mono" value={valuesText(b.values)} spellcheck="false" placeholder="code=AUTHORISED" onchange={(ev) => (b.values = parseValues(ev.currentTarget.value))} />
        <input aria-label={t('pg.f.set', { n: i + 1 })} class="mono" value={setText(b.set)} spellcheck="false" placeholder={'status={value.code}'} onchange={(ev) => (b.set = parseSet(ev.currentTarget.value))} />
        <label class="check"><input type="checkbox" bind:checked={() => !!b.no_callback, (v) => (b.no_callback = v || undefined)} /> {t('pg.f.noCallback')}</label>
        {#if p.buttons.length > 1}<Button size="sm" variant="ghost" icon="close" title={t('pg.f.buttonRemove', { n: i + 1 })} onclick={() => (p.buttons = p.buttons.filter((_, j) => j !== i))}>{t('pg.f.buttonRemove', { n: i + 1 })}</Button>{/if}
      </div>
    {/each}
    {#if fieldErr('buttons')}<p class="err">{fieldErr('buttons')}</p>{/if}
    {#if p.buttons.length < 6}<Button size="sm" icon="plus" onclick={() => (p.buttons = [...p.buttons, { action: '', label: '' }])}>{t('pg.f.buttonAdd')}</Button>{/if}
    <p class="subtle">{t('pg.f.valuesHint')}</p>
    <p class="subtle">{t('pg.f.setHint')}</p>
  </fieldset>

  <fieldset>
    <legend>{t('pg.f.callback')}</legend>
    <label class="check"><input type="checkbox" checked={!!p.callback} onchange={(ev) => toggleCallback(ev.currentTarget.checked)} /> {t('pg.f.callbackOn')}</label>
    <p class="subtle">{t('pg.f.callbackHint')}</p>
    {#if p.callback}
      <div class="grid3">
        <Field label={t('pg.f.method')}>
          {#snippet children({ id, describedby })}
            <select {id} aria-describedby={describedby} bind:value={p.callback!.method}>
              {#each ['POST', 'PUT', 'PATCH', 'GET', 'DELETE'] as m (m)}<option value={m}>{m}</option>{/each}
            </select>
          {/snippet}
        </Field>
        <Field label={t('pg.f.bodyType')} hint={t('pg.f.bodyTypeHint')}>
          {#snippet children({ id, describedby })}
            <select {id} aria-describedby={describedby} value={p.callback!.body_type || 'json'} onchange={(ev) => (p.callback!.body_type = ev.currentTarget.value as PageCallback['body_type'])}>
              <option value="json">json</option>
              <option value="form">form</option>
              <option value="text">text</option>
            </select>
          {/snippet}
        </Field>
      </div>
      <Field label={t('pg.f.callbackUrl')} hint={t('pg.f.callbackUrlHint')} error={fieldErr('callback.url')}>
        {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" bind:value={p.callback!.url} spellcheck="false" placeholder="https://app.test/api/pay/notify" />{/snippet}
      </Field>
      <div class="sub">
        <b>{t('pg.f.headers')}</b>
        {#each headerRows as [k, v], j (j)}
          <div class="rowline">
            <input aria-label={t('pg.f.headerName', { n: j + 1 })} class="mono" value={k} spellcheck="false" onchange={(ev) => setHeader(k, ev.currentTarget.value.trim(), v)} />
            <input aria-label={t('pg.f.headerValue', { n: j + 1 })} class="mono" value={v} spellcheck="false" oninput={(ev) => setHeader(k, k, ev.currentTarget.value)} />
            <Button size="sm" variant="ghost" icon="close" title={t('pg.f.headerRemove', { n: j + 1 })} onclick={() => dropHeader(k)}>{t('pg.f.headerRemove', { n: j + 1 })}</Button>
          </div>
        {/each}
        {#if fieldErr('callback.headers')}<p class="err">{fieldErr('callback.headers')}</p>{/if}
        <Button size="sm" icon="plus" onclick={() => setHeader('', `X-Header-${headerRows.length + 1}`, '')}>{t('pg.f.headerAdd')}</Button>
      </div>
      <Field label={t('pg.f.body')} hint={t('pg.f.bodyHint')} error={fieldErr('callback.body')}>
        {#snippet children({ id, describedby })}<textarea {id} aria-describedby={describedby} class="mono" rows="3" spellcheck="false" value={p.callback!.body ?? ''} oninput={(ev) => (p.callback!.body = ev.currentTarget.value)}></textarea>{/snippet}
      </Field>

      <label class="check"><input type="checkbox" checked={!!p.callback.hmac} onchange={(ev) => toggleHmac(ev.currentTarget.checked)} /> {t('pg.f.hmacOn')}</label>
      <p class="subtle">{t('pg.f.hmacHint')}</p>
      {#if p.callback.hmac}
        <div class="grid3">
          <Field label={t('pg.f.hmacHeader')} error={fieldErr('callback.hmac.header')}>
            {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" bind:value={p.callback!.hmac!.header} spellcheck="false" />{/snippet}
          </Field>
          <Field label={t('pg.f.hmacKey')} hint={keyStored ? t('pg.f.hmacKeyKeep') : t('pg.f.hmacKeyNew')} error={fieldErr('callback.hmac.key')}>
            {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} type="password" autocomplete="new-password" bind:value={p.callback!.hmac!.key} maxlength="256" />{/snippet}
          </Field>
          <Field label={t('pg.f.hmacPrefix')} hint={t('pg.f.hmacPrefixHint')} error={fieldErr('callback.hmac.prefix')}>
            {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" value={p.callback!.hmac!.prefix ?? ''} maxlength="32" spellcheck="false" placeholder="sha256=" oninput={(ev) => (p.callback!.hmac!.prefix = ev.currentTarget.value)} />{/snippet}
          </Field>
          <Field label={t('pg.f.hmacAlgorithm')}>
            {#snippet children({ id, describedby })}
              <select {id} aria-describedby={describedby} value={p.callback!.hmac!.algorithm || 'sha256'} onchange={(ev) => (p.callback!.hmac!.algorithm = ev.currentTarget.value as 'sha256')}>
                {#each ['sha256', 'sha1', 'sha512'] as a (a)}<option value={a}>{a}</option>{/each}
              </select>
            {/snippet}
          </Field>
          <Field label={t('pg.f.hmacEncoding')}>
            {#snippet children({ id, describedby })}
              <select {id} aria-describedby={describedby} value={p.callback!.hmac!.encoding || 'hex'} onchange={(ev) => (p.callback!.hmac!.encoding = ev.currentTarget.value as 'hex')}>
                {#each ['hex', 'base64'] as a (a)}<option value={a}>{a}</option>{/each}
              </select>
            {/snippet}
          </Field>
        </div>
      {/if}
    {/if}
  </fieldset>

  <fieldset>
    <legend>{t('pg.f.links')}</legend>
    <p class="subtle">{t('pg.f.linksHint')}</p>
    {#each p.links ?? [] as l, i (i)}
      <div class="rowline">
        <input aria-label={t('pg.f.linkService', { n: i + 1 })} class="mono" bind:value={l.service} spellcheck="false" placeholder="payments-ext" />
        <input aria-label={t('pg.f.linkOp', { n: i + 1 })} class="mono" bind:value={l.op} spellcheck="false" placeholder="POST /v1/sessions" />
        <input aria-label={t('pg.f.linkPath', { n: i + 1 })} class="mono" bind:value={l.path} spellcheck="false" placeholder="$.redirectUrl" />
        <input aria-label={t('pg.f.linkRefPath', { n: i + 1 })} class="mono" value={l.ref_path ?? ''} spellcheck="false" placeholder="$.paymentId" oninput={(ev) => (l.ref_path = ev.currentTarget.value)} />
        <input aria-label={t('pg.f.linkBase', { n: i + 1 })} class="mono" value={l.base_url ?? ''} spellcheck="false" placeholder="http://mock.test:8480" oninput={(ev) => (l.base_url = ev.currentTarget.value)} />
        <select aria-label={t('pg.f.linkReturnFromKind', { n: i + 1 })} value={l.return_from?.from ?? ''} onchange={(ev) => setReturnFrom(l, ev.currentTarget.value)}>
          <option value="">{t('pg.f.linkReturnNone')}</option>
          {#each ['req.body', 'req.query', 'req.headers'] as k (k)}<option value={k}>{k}</option>{/each}
        </select>
        {#if l.return_from}<input aria-label={t('pg.f.linkReturnFrom', { n: i + 1 })} class="mono" value={l.return_from.path ?? l.return_from.name ?? ''} spellcheck="false" placeholder={l.return_from.from === 'req.body' ? '$.returnUrl' : 'returnUrl'} oninput={(ev) => setReturnWhere(l, ev.currentTarget.value)} />{/if}
        <input aria-label={t('pg.f.linkEntity', { n: i + 1 })} class="mono" value={l.entity ?? ''} spellcheck="false" placeholder="payment" oninput={(ev) => (l.entity = ev.currentTarget.value)} />
        <Button size="sm" variant="ghost" icon="close" title={t('pg.f.linkRemove', { n: i + 1 })} onclick={() => (p.links = (p.links ?? []).filter((_, j) => j !== i))}>{t('pg.f.linkRemove', { n: i + 1 })}</Button>
      </div>
    {/each}
    {#if fieldErr('links')}<p class="err">{fieldErr('links')}</p>{/if}
    <Button size="sm" icon="plus" onclick={() => (p.links = [...(p.links ?? []), { service: '', op: '', path: '$.redirectUrl' }])}>{t('pg.f.linkAdd')}</Button>
    <p class="subtle">{t('pg.f.linkMoreHint')}</p>
  </fieldset>

  <fieldset>
    <legend>{t('pg.f.auto')}</legend>
    <p class="subtle">{t('pg.f.autoHint')}</p>
    {#each autoRows as [k, a], i (i)}
      <div class="rowline">
        <input aria-label={t('pg.f.autoScenario', { n: i + 1 })} class="mono" value={k} spellcheck="false" placeholder="*" onchange={(ev) => setAuto(k, ev.currentTarget.value.trim(), a)} />
        <select aria-label={t('pg.f.autoAction', { n: i + 1 })} value={a} onchange={(ev) => setAuto(k, k, ev.currentTarget.value)}>
          {#each actions as x (x)}<option value={x}>{x}</option>{/each}
          {#if !actions.includes(a)}<option value={a}>{a}</option>{/if}
        </select>
        <Button size="sm" variant="ghost" icon="close" title={t('pg.f.autoRemove', { n: i + 1 })} onclick={() => dropAuto(k)}>{t('pg.f.autoRemove', { n: i + 1 })}</Button>
      </div>
    {/each}
    {#if fieldErr('auto')}<p class="err">{fieldErr('auto')}</p>{/if}
    <Button size="sm" icon="plus" disabled={!actions.length} onclick={() => setAuto(`${uid}-new`, autoRows.some(([k]) => k === '*') ? `scenario-${autoRows.length + 1}` : '*', actions[0] ?? '')}>{t('pg.f.autoAdd')}</Button>
  </fieldset>

  {#if problems.length}
    <div class="callout warn" role="status">
      <b>{t('pg.f.problems')}</b>
      <ul>{#each problems as x, i (i)}<li>{tk(`pg.err.${x.code}`, { item: x.item ?? '' }, x.code)}</li>{/each}</ul>
    </div>
  {/if}
  {#if error}<p class="callout danger" role="alert">{error}</p>{/if}
  <div class="actions">
    <Button variant="ghost" onclick={oncancel}>{t('common.cancel')}</Button>
    <Button type="submit" variant="primary" loading={busy} disabled={problems.length > 0}>{t('pg.save')}</Button>
  </div>
</form>

<style>
  .pform { border: 1px solid var(--border-strong); border-radius: var(--r-md); padding: var(--s-3) var(--s-4); }
  fieldset { border: 0; border-top: 1px solid var(--border); padding: var(--s-3) 0 0; margin: 0; display: flex; flex-direction: column; gap: var(--s-2); }
  fieldset:first-of-type { border-top: 0; padding-top: 0; }
  legend { font-weight: 700; padding: 0; }
  fieldset p { margin: 0; }
  .grid2 { display: grid; gap: var(--s-3); grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr)); }
  .grid3 { display: grid; gap: var(--s-3); grid-template-columns: repeat(auto-fit, minmax(min(100%, 160px), 1fr)); }
  .rowline { display: flex; flex-wrap: wrap; gap: var(--s-2); align-items: center; }
  .rowline input { flex: 1; min-width: 7rem; }
  .rowline select { width: auto; }
  .check { display: inline-flex; align-items: center; gap: 4px; }
  .sub { display: flex; flex-direction: column; gap: var(--s-2); }
  .err { color: var(--danger); font-size: 0.86rem; }
  .actions { display: flex; gap: var(--s-2); justify-content: flex-end; }
  textarea { width: 100%; }
  .mono { font-family: var(--font-mono); }
</style>
