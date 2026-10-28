<script lang="ts">
  import InfoTip from '../components/InfoTip.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Badge from '../components/Badge.svelte';
  import Loading from '../components/Loading.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { fmtNum, fmtPct } from '../lib/format';
  import ScopeNote from '../components/ScopeNote.svelte';
  import { scopeGroups } from '../lib/scope.svelte';

  // The latest build of the filtered group: the profiles of another team never show here.
  const set = resource(() => api.archetypes.get(scopeGroups()));
  const ok = $derived((set.data?.archetypes ?? []).filter((a) => !a.belowK));
  const low = $derived((set.data?.archetypes ?? []).filter((a) => a.belowK));
  const maxSize = $derived(Math.max(1, ...ok.map((a) => a.size ?? 0)));
  const colors: Record<string, string> = { happy: 'c-ok', cancelled: 'c-warn', 'never-shipped': 'c-bad' };
</script>

<PageHeader title={t('arch.title')} description={t('arch.desc')} help="archetypes" breadcrumbs={[{ label: t('nav.archetypes') }]} updatedAt={set.updatedAt} onrefresh={set.reload} refreshing={set.loading} />

{#if set.data}
  <div class="stack">
    <ScopeNote />
    <p class="callout" role="note">{t('arch.auto')}</p>
    {#if set.data.group}<p class="subtle">{t('arch.ofGroup', { group: set.data.group })}</p>{/if}
    <p class="callout ok"><b>k = {set.data.kMin}</b> <InfoTip id="arch.k" /> — {t('arch.kHint', { k: set.data.kMin })}</p>

    <div class="grid">
      {#each ok as a (a.id)}
        <Card>
          <div class="stack-sm">
            <div class="row spread"><code>{a.id}</code><Badge tone="success">k ≥ {set.data.kMin}</Badge></div>
            <h2 class="fs-3">{a.label}</h2>
            <div class="size">
              <div class="track" role="img" aria-label={t('arch.sizeOf', { n: a.size ?? 0 })}><div class="fill" style:width="{((a.size ?? 0) / maxSize) * 100}%"></div></div>
              <b class="num">{fmtNum(a.size ?? 0)}</b> <span class="subtle">{t('arch.users')}</span>
            </div>
            <dl>
              <div><dt>{t('arch.opm')}</dt><dd>{a.features.ordersPerMonth}</dd></div>
              <div><dt>{t('arch.hours')}</dt><dd>{a.features.activeHours}</dd></div>
            </dl>
            <div>
              <span class="subtle">{t('arch.mix')}</span> <InfoTip id="arch.mix" />
              <div class="mix" role="img" aria-label={Object.entries(a.features.outcomesMix).map(([k, v]) => `${k} ${fmtPct(v, 0)}`).join(', ')}>
                {#each Object.entries(a.features.outcomesMix) as [k, v] (k)}<span class={colors[k] ?? 'c-ok'} style:width="{v * 100}%" title="{k} {fmtPct(v, 0)}"></span>{/each}
              </div>
              <div class="legend subtle">{#each Object.entries(a.features.outcomesMix) as [k, v] (k)}<span><i class={colors[k] ?? 'c-ok'}></i>{k} {fmtPct(v, 0)}</span>{/each}</div>
            </div>
          </div>
        </Card>
      {/each}
    </div>

    {#if low.length}
      <Card title={t('arch.lowTitle', { n: low.length })} subtitle={t('arch.lowHint', { k: set.data.kMin })}>
        <ul class="low">
          {#each low as a (a.id)}
            <li><code>{a.id}</code> <span class="muted">{a.label}</span> <Badge tone="warning">{tk('arch.merged')}</Badge> <span class="subtle">&lt; {set.data.kMin}</span></li>
          {/each}
        </ul>
      </Card>
    {/if}
  </div>
{:else}
  <Loading error={set.error} onretry={set.reload} />
{/if}

<style>
  .grid { grid-template-columns: repeat(auto-fill, minmax(min(100%, 19rem), 1fr)); }
  .size { display: flex; align-items: center; gap: var(--s-2); }
  .track { flex: 1; height: 0.5rem; background: var(--surface-3); border-radius: 999px; overflow: hidden; }
  .fill { height: 100%; background: var(--accent); border-radius: 999px; }
  dl { margin: 0; display: grid; grid-template-columns: 1fr 1fr; gap: var(--s-2); }
  dt { font-size: 0.75rem; color: var(--fg-subtle); text-transform: uppercase; font-weight: 600; }
  dd { margin: 0; font-weight: 600; }
  .mix { display: flex; height: 0.7rem; border-radius: 999px; overflow: hidden; margin: 4px 0; background: var(--surface-3); }
  .mix span { display: block; height: 100%; }
  .c-ok { background: var(--success); }
  .c-warn { background: var(--warning); }
  .c-bad { background: var(--danger); }
  .legend { display: flex; gap: var(--s-3); flex-wrap: wrap; }
  .legend i { display: inline-block; width: 0.55rem; height: 0.55rem; border-radius: 50%; margin-right: 4px; }
  .low { margin: 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: var(--s-2); }
</style>
