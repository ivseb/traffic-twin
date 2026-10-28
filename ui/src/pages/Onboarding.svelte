<script lang="ts">
  import InfoTip from '../components/InfoTip.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Stepper from '../components/Stepper.svelte';
  import Button from '../components/Button.svelte';
  import Icon, { type IconName } from '../components/Icon.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import Badge from '../components/Badge.svelte';
  import DiffView from '../components/DiffView.svelte';
  import Field from '../components/Field.svelte';
  import Loading from '../components/Loading.svelte';
  import NewHostsHint from '../components/NewHostsHint.svelte';
  import PolicyApproval from '../components/PolicyApproval.svelte';
  import ApproverHelp from '../components/ApproverHelp.svelte';
  import ApprovalNextStep from '../components/ApprovalNextStep.svelte';
  import IdentityControl from '../components/IdentityControl.svelte';
  import { uniqBy } from '../lib/assist';
  import { pendingOpeningDrafts } from '../lib/approval';
  import { t, tk, type MsgKey } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { AssistService, DiffEntry, EnrollmentToken, HostsDiscovery, ObserveStatus, OnboardingStatus, PolicyActionKind, PolicyAssist, PolicyChoice, PolicySuggestion, PolicyVersion, Problem, Source, SourceChoice, ValueReason } from '../lib/api';
  import Switch from '../components/Switch.svelte';
  import { can, errorMessage, toast, toastError } from '../lib/stores.svelte';
  import { currentChoices, diffChoices, formatChoice, hostsDiff, opensData, sameChoice } from '../lib/policy';
  import { opensField, safeProposal } from '../lib/observe';
  import { statesFacts } from '../lib/codes';
  import { checkBase, exactBaseUrl, validServiceName } from '../lib/hosts';
  import { href } from '../lib/router';
  import { loc } from '../lib/router.svelte';
  import { fmtNum, fmtDate, fmtPct } from '../lib/format';
  import { resource } from '../lib/resource.svelte';
  import { loadWizard, saveWizard, clearWizard, declareDefault, rememberDeclare, rememberedDeclare, visibleAssistServices, loadTokenMeta, saveTokenMeta, clearTokenMeta, clockTime, suggestGroup, type WizardState } from '../lib/wizard';

  const settings = resource(() => api.settings.get());
  // How many approvals a change that opens data needs (read from keyguard).
  const required = $derived(settings.data?.approvals.openingRequired ?? 2);
  // Groups that already have a policy: the assistant can be opened for them without a new token.
  const known = resource(() => api.policies.list());
  // The rules of the group: with the code fields of its policy they tell whether the states are already there (usability #5).
  const groupRules = resource(() => (group ? api.rules.list([group]).catch(() => []) : Promise.resolve([])));
  const knownGroups = $derived([...new Set((known.data ?? []).flatMap((p) => p.groups ?? []))].sort());

  interface CardDef {
    id: SourceChoice;
    icon: IconName;
    title?: string;
    titleKey?: MsgKey;
    descKey: MsgKey;
    req?: string;
    reqKey?: MsgKey;
  }
  const CARDS: CardDef[] = [
    { id: 'sdk-node', icon: 'services', title: 'Node.js', descKey: 'wiz.src.sdk.desc', req: 'Node.js 20+ (24+ per il corpo completo di fetch) · http, undici, Express, Fastify' },
    { id: 'sdk-python', icon: 'services', title: 'Python', descKey: 'wiz.src.sdk.desc', req: 'Python 3.9+ · requests, httpx, ASGI/WSGI' },
    { id: 'sdk-java', icon: 'services', title: 'Java', descKey: 'wiz.src.sdk.desc', req: 'Java 17+ · javaagent o filtro servlet' },
    { id: 'sdk-dotnet', icon: 'services', title: '.NET', descKey: 'wiz.src.sdk.desc', req: '.NET 8+ · ASP.NET Core, HttpClient' },
    { id: 'sdk-go', icon: 'services', title: 'Go', descKey: 'wiz.src.sdk.desc', req: 'Go 1.25+ · http.Handler, RoundTripper' },
    { id: 'sdk-php', icon: 'services', title: 'PHP', descKey: 'wiz.src.sdk.desc', req: 'PHP 8.1+ · PSR-15, Guzzle' },
    { id: 'egress', icon: 'sources', titleKey: 'wiz.src.egress.title', descKey: 'wiz.src.egress.desc', reqKey: 'wiz.src.egress.req' },
    { id: 'obi', icon: 'audit', titleKey: 'wiz.src.obi.title', descKey: 'wiz.src.obi.desc', reqKey: 'wiz.src.obi.req' },
    { id: 'k8s-inject', icon: 'worlds', titleKey: 'wiz.src.k8s.title', descKey: 'wiz.src.k8s.desc', reqKey: 'wiz.src.k8s.req' },
    { id: 'import-har', icon: 'download', titleKey: 'wiz.src.har.title', descKey: 'wiz.src.har.desc', reqKey: 'wiz.src.har.req' },
  ];


  // The wizard survives a reload or a visit to another page (glossary, policies): its state is kept in the tab
  // (sessionStorage), never on the server and never a value of the traffic. `?group=<g>&step=<n>` opens a group directly.
  const saved: WizardState | null = loadWizard();

  // An advanced step (3+) needs the assistant: goTo() loads it and only then shows the step, so the page never
  // starts on an empty step (usability test #4, m6). Until then the last simple step is shown.
  let step = $state(Math.min(saved?.step ?? 0, 2));
  // The step being opened by goTo() (loading or failed): the page says so instead of staying blank.
  let opening = $state<number | null>(null);
  // The happy path has three steps (spec v1.6, policy.md §7: no policy and no approval to start): Connect, Start,
  // Listening. The policy steps are "Advanced": they show in the stepper only once the person opens them.
  const stepDefs = $derived([
    { id: 'source', label: t('obs.step.connect') },
    { id: 'install', label: t('obs.step.install') },
    { id: 'wait', label: t('obs.step.listen') },
    ...(step >= 3
      ? [
          { id: 'discover', label: t('wiz.step.discover') },
          { id: 'policy', label: t('wiz.step.policy') },
          { id: 'review', label: t('wiz.step.review') },
        ]
      : []),
  ]);
  let choice = $state<SourceChoice | null>(saved?.choice ?? null);
  // Empty at the start: a name typed here may be the group of another team (joining it means using its policy). The
  // field suggests one from the service name; nothing is prefilled.
  let group = $state(saved?.group ?? '');
  // Service names the group may use (comma separated); empty = the name the first source enrolls with.
  let svcNames = $state(saved?.svcNames ?? '');
  // Sampling of the starter policy: 10% by default (enough users for k with about 400 users); a trial takes everything.
  let samplingRate = $state(saved?.samplingRate ?? '0.1');
  let busy = $state(false);
  let token = $state<EnrollmentToken | null>(saved?.token ?? null);
  // What survives a new tab or a restart: not the secret (shown once, the server keeps only its hash) but when it was
  // made and when it expires, so the page can say so and offer a new one.
  let tokenMeta = $state(loadTokenMeta());
  const metaExpired = $derived(!!tokenMeta && Date.parse(tokenMeta.expiresAt) < Date.now());
  let starter = $state<PolicyVersion | null>(saved?.starter ?? null);
  let status = $state<OnboardingStatus | null>(null);
  // Sources of the group already connected (any token): they are enough to go on.
  let groupSources = $state<Source[]>([]);
  // The policy versions of the group (loadStarter): the active one says whether the sources capture already.
  let groupPolicies = $state<PolicyVersion[]>([]);
  // Twin selection of the external services of this group: as chosen, and as stored by tt-core.
  let twin = $state<Record<string, boolean>>(saved?.twin ?? {});
  let twinBefore = $state<Record<string, boolean>>(saved?.twinBefore ?? {});
  let assist = $state<PolicyAssist | null>(null);
  let choices = $state<Record<string, PolicyChoice>>(saved?.choices ?? {});
  // Per service (`service`) and per operation (`service \0 op`): declared by the new policy or not.
  let include = $state<Record<string, boolean>>(saved?.include ?? {});
  // External services not declared yet: the policy name, the scheme (never guessed) or the exact base.
  let svcName = $state<Record<string, string>>(saved?.svcName ?? {});
  let svcScheme = $state<Record<string, '' | 'http' | 'https'>>(saved?.svcScheme ?? {});
  let svcBase = $state<Record<string, string>>(saved?.svcBase ?? {});
  // Who the user is (identity.subject): none, a candidate the assistant saw, or typed by the person.
  let idMode = $state<'none' | 'pick'>(saved?.idMode ?? 'none');
  let idFrom = $state<'header' | 'cookie'>(saved?.idFrom ?? 'header');
  let idName = $state(saved?.idName ?? '');
  let idClaim = $state(saved?.idClaim ?? '');
  let proposal = $state<PolicyVersion | null>(saved?.proposal ?? null);
  // The person went back from the review to change the draft already proposed: sending again replaces it (one pending draft).
  let editingDraft = $state(false);
  /** The pending draft of this group (not the starter one): what the next submit adds to. */
  const draftVersion = $derived.by(() => {
    if (proposal && proposal.status === 'draft') return proposal;
    return (known.data ?? []).filter((p) => p.status === 'draft' && p.origin !== 'starter' && (p.groups ?? []).includes(group)).sort((a, b) => b.version - a.version)[0] ?? null;
  });
  let preview = $state<{ before: string; after: string; skipped: string[]; opensValues?: boolean; valueReasons?: ValueReason[]; approvalsRequired?: number } | null>(null);
  let loadError = $state<Error | undefined>();
  // hosts.discovery of the policy: what it says today and what the person picked (auto = every host visible, off = strict).
  let hostsCurrent = $state<HostsDiscovery>(saved?.hostsCurrent ?? 'auto');
  let hostsMode = $state<HostsDiscovery>(saved?.hostsMode ?? 'auto');
  let hostsLoaded = $state(saved?.hostsLoaded ?? false);

  $effect(() => {
    saveWizard({
      step, choice, group, svcNames, samplingRate, token, starter, twin, twinBefore, choices, include, svcName, svcScheme, svcBase,
      idMode, idFrom, idName, idClaim, proposal, hostsCurrent, hostsMode, hostsLoaded,
    });
  });

  const groupValid = $derived(/^[a-z0-9][a-z0-9-]{0,62}$/.test(group));
  const groupSuggested = $derived(suggestGroup(svcNames));
  const groupPlaceholder = $derived(groupSuggested || t('wiz.source.groupPlaceholder'));
  // The group exists already (a policy is bound to it): whoever enters it uses that policy, whoever made it.
  const groupExists = $derived(group !== '' && knownGroups.includes(group));
  const names = $derived(svcNames.split(/[\s,]+/).filter(Boolean));
  const namesValid = $derived(names.every((n) => /^[a-z0-9][a-z0-9._-]{0,62}$/.test(n)));
  const eventsGoal = 20;
  const connected = $derived(groupSources.filter((s) => !s.revoked && !!s.policy));
  const suggestions = $derived(assist?.suggestions ?? []);
  const startStep = Number(loc.query.step ?? '');

  // Source cards are a radio group: one tab stop, arrow keys move and select (WAI-ARIA radio pattern).
  function cardKeys(e: KeyboardEvent): void {
    const keys: Record<string, number> = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
    if (!(e.key in keys)) return;
    e.preventDefault();
    const i = Math.max(0, CARDS.findIndex((c) => c.id === choice));
    const next = CARDS[(i + keys[e.key] + CARDS.length) % CARDS.length];
    choice = next.id;
    queueMicrotask(() => (e.currentTarget as HTMLElement).querySelector<HTMLElement>('[aria-checked="true"]')?.focus());
  }

  // ---------------------------------------------------------------- step 1 -> 2
  async function createToken(): Promise<void> {
    if (!choice) return;
    busy = true;
    try {
      const made = await api.onboarding.createToken(choice, group, names.length ? names : undefined, { samplingRate });
      token = { ...made, createdAt: made.createdAt ?? new Date().toISOString() };
      tokenMeta = saveTokenMeta(token);
      status = null;
      starter = null;
      await loadStarter();
      step = 1;
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }

  /** A new token for the same group and kind as the one remembered (the secret of the old one cannot be shown again). */
  async function regenerate(m = tokenMeta): Promise<void> {
    if (m) {
      choice = m.choice;
      group = m.group;
    }
    await createToken();
  }

  // The starter policy is a draft like any opening change: it is approved here, right after the token, before the
  // source can capture. For a group created elsewhere: its newest draft, if any.
  async function loadStarter(): Promise<void> {
    const sp = token?.starterPolicy;
    try {
      const all = await api.policies.list([group]);
      // Only the starter policy itself: a later draft of the group (one that opens values) is not what the source
      // waits for to capture (usability test #4, m5); it has its own «Prossimo passo» card.
      starter =
        (sp ? all.find((p) => p.policyId === sp.policyId && p.version === sp.version) : undefined) ??
        all.filter((p) => p.status === 'draft' && p.origin === 'starter' && (p.groups ?? []).includes(group)).sort((a, b) => b.version - a.version)[0] ??
        null;
      groupPolicies = all;
    } catch {
      starter = null;
    }
  }

  async function loadGroupSources(): Promise<void> {
    try {
      groupSources = (await api.sources.list()).filter((s) => s.group === group);
    } catch {
      groupSources = [];
    }
  }

  // ---------------------------------------------------------------- step 3: live status
  // Server-sent events when the server offers them, polling otherwise (the adapter decides).
  $effect(() => {
    if (step !== 2 || !token) return;
    return api.onboarding.watch(
      token.tokenId,
      (s) => (status = s),
      (e) => (loadError = e),
    );
  });
  // A source of the group connected with another token also counts; the starter draft may be approved meanwhile.
  $effect(() => {
    if (step !== 2) return;
    void loadGroupSources();
    void loadStarter();
    const h = setInterval(() => void loadGroupSources(), 5000);
    return () => clearInterval(h);
  });

  // ---------------------------------------------------------------- step 3: the observe phase (policy.md §7)
  let observe = $state<ObserveStatus | null>(null);
  let autoBusy = $state(false);
  async function setObserveAuto(auto: boolean): Promise<void> {
    if (!group) return;
    autoBusy = true;
    try {
      observe = await api.onboarding.setObserveAuto(group, auto);
    } catch (e) {
      toastError(e);
    } finally {
      autoBusy = false;
    }
  }
  async function loadObserve(): Promise<void> {
    if (!group) return;
    try {
      observe = await api.onboarding.observe(group);
    } catch {
      /* an older server without the endpoint: the checks above still say what arrives */
    }
  }
  $effect(() => {
    if (step !== 2 || !group) return;
    void loadObserve();
    const h = setInterval(() => void loadObserve(), 4000);
    return () => clearInterval(h);
  });
  const ownServices = $derived((observe?.services ?? []).filter((s) => s.kind === 'inbound'));
  const extServices = $derived((observe?.services ?? []).filter((s) => s.kind !== 'inbound'));
  const maskedPart = (m: ObserveStatus['masked'][number]) => (m.kind === 'path' ? t('obs.part.path') : tk(`obs.part.${m.part}`, undefined, m.part));
  const maskedField = (m: ObserveStatus['masked'][number]) => (m.kind === 'body' ? m.field.replace(/^\$\.?/, '') || m.field : m.field);
  // Raising the sampling while no value leaves in clear opens nothing: it applies at once.
  const obsSampling = $derived(observe?.sampling);
  // Only once users are counted (the identity is set): before, the advice has nothing to rest on.
  const obsSuggestedBp = $derived(obsSampling && obsSampling.source === 'subject' && obsSampling.sampledSubjects > 0 && !obsSampling.enough && obsSampling.suggestedBp > obsSampling.currentBp ? obsSampling.suggestedBp : 0);
  async function raiseObserveSampling(): Promise<void> {
    if (!obsSuggestedBp) return;
    busy = true;
    try {
      await api.onboarding.assist(group);
      const v = await api.policies.propose({ group, choices: [], services: [], samplingBp: obsSuggestedBp });
      toast(v.status === 'active' ? t('obs.sampling.raised', { rate: fmtPct(obsSuggestedBp / 10000, 2) }) : t('obs.sampling.raisedDraft', { rate: fmtPct(obsSuggestedBp / 10000, 2) }));
      known.reload();
      await loadObserve();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
  const reasonText = (r: ValueReason) => tk(`obs.reason.${r.code}`, undefined, r.code);

  type CheckState = 'done' | 'active' | 'pending' | 'problem';
  const checks = $derived.by(() => {
    const s = status;
    const problem = (s?.problems.length ?? 0) > 0;
    const enrolled = !!s?.enrolled || connected.length > 0;
    const policy = !!s?.policyReceived || connected.length > 0;
    const n = s?.firstEvents ?? 0;
    const st = (done: boolean, prev: boolean): CheckState => (done ? 'done' : prev ? (problem ? 'problem' : 'active') : 'pending');
    return [
      { id: 'enrolled', label: t('wiz.wait.enrolled'), detail: t('wiz.wait.enrolledHint'), state: st(enrolled, true) },
      { id: 'policy', label: t('wiz.wait.policy'), detail: t('wiz.wait.policyHint'), state: st(policy, enrolled) },
      { id: 'events', label: t('wiz.wait.events', { n: Math.min(n, eventsGoal), goal: eventsGoal }), detail: t('wiz.wait.eventsHint'), state: st(n >= eventsGoal || connected.length > 0, policy) },
    ];
  });
  /** The problems of the source in the UI language (the server's English text only when there is no translation). */
  const problemText = (p: Problem) => ({ title: tk(`problem.${p.code}`, undefined, p.message), hint: tk(`problem.${p.code}.hint`, undefined, p.hint ?? '') });
  // The version the sources of the group capture with (the newest active one), if any.
  const activeVersion = $derived(groupPolicies.filter((p) => p.status === 'active' && (p.groups ?? []).includes(group)).sort((a, b) => b.version - a.version)[0] ?? null);
  // The starter still waits for its approval only while nothing of the group is active and no source captures.
  const needsApproval = $derived(!!starter && starter.status === 'draft' && !activeVersion && connected.length === 0);
  // Drafts of the group that open values and wait for approvals (B1): the «Prossimo passo» card of «In ascolto».
  const openingDrafts = $derived(pendingOpeningDrafts(groupPolicies, [group]));

  // ---------------------------------------------------------------- navigation
  async function loadAssist(): Promise<void> {
    const a = await api.onboarding.assist(group);
    const prev = assist;
    assist = a;
    // Keep what the person already decided (also across a reload); new fields start from the proposal.
    const key = (s: PolicySuggestion) => `${s.service}\u0000${s.op}\u0000${s.part}\u0000${s.path}`;
    const old = new Map((prev?.suggestions ?? []).map((s) => [key(s), choices[s.id]]));
    const kept = !prev ? choices : {};
    choices = Object.fromEntries(a.suggestions.map((s) => [s.id, old.get(key(s)) ?? kept[s.id] ?? safeProposal(s)]));
    for (const s of a.services) {
      // "Declare in the policy": the person's own choice for this policy (kept in the tab across reloads and new
      // versions), else the server's default (preselect; a stale host is never checked by itself).
      include[s.service] = rememberedDeclare(a.policyId, s.service) ?? declareDefault(s);
      svcName[s.service] ??= s.name;
      svcScheme[s.service] ??= '';
      svcBase[s.service] ??= '';
      for (const o of s.ops) include[`${s.service}\u0000${o.op}`] ??= true;
    }
    if (!prev && !idName && !a.hasIdentity) {
      // The source the detection picks (policy.md §7.4); an older server without a pick: its first candidate.
      const c = a.identityBest ?? (a.identityCandidates.some((x) => x.score !== undefined) ? undefined : a.identityCandidates[0]);
      if (c) {
        idMode = 'pick';
        idFrom = c.from;
        idName = c.name;
        idClaim = c.claim ?? ('jwt' in c && c.jwt ? 'sub' : '');
      }
    }
  }

  // The blocks shown: one folded into another (merged_patterns) is named in that block's note, not shown twice.
  const shownServices = $derived(visibleAssistServices(assist?.services ?? []));
  const foldedServices = $derived(new Set((assist?.services ?? []).filter((s) => !shownServices.includes(s)).map((s) => s.service)));
  /** External services of this group (from the assistant, never the services of other teams). */
  const externals = $derived(shownServices.filter((s) => s.kind === 'external'));
  const twinKey = (s: AssistService) => (s.declared ? s.name : s.service);

  async function goTo(n: number): Promise<void> {
    loadError = undefined;
    busy = true;
    if (n >= 3) opening = n;
    try {
      if (n === 3) {
        // The twin choice is per (group, service): this group's rows only, never another team's.
        const [, svcs] = await Promise.all([loadAssist(), api.services.list([group]).catch(() => [])]);
        const cur = new Map(svcs.map((s) => [s.name, s.twin]));
        for (const s of externals) {
          const k = twinKey(s);
          twinBefore[k] = cur.get(k) ?? true;
          twin[k] ??= twinBefore[k];
        }
      }
      if (n === 4 && step === 3 && can('sources.manage')) {
        // Only what changed, only for this group's external services, in parallel.
        const changed = externals.map(twinKey).filter((k) => twin[k] !== undefined && twin[k] !== twinBefore[k]);
        await Promise.all(changed.map((k) => api.services.setTwin(k, !!twin[k], group)));
        for (const k of changed) twinBefore[k] = !!twin[k];
      }
      if (n >= 4) known.reload();
      if (n >= 3 && !assist) await loadAssist();
      if (n >= 4 && !hostsLoaded) {
        hostsCurrent = hostsMode = await api.policies.hostsDiscovery(group);
        hostsLoaded = true;
      }
      if (n === 5) {
        // A proposal already signed belongs to the past: the next one starts fresh.
        if (proposal && proposal.status !== 'draft') proposal = null;
        preview = await api.policies.preview(proposeInput());
      }
      step = n;
      opening = null;
    } catch (e) {
      loadError = e instanceof Error ? e : new Error(String(e));
    } finally {
      busy = false;
    }
  }

  // Opening an existing group (from Sources → Policy, or the list below): straight to its services and assistant.
  function openGroup(g: string, n = 3): void {
    reset();
    group = g;
    void goTo(n);
  }
  // A link to the assistant (?step=3/4) without a valid group: say which group is needed (m6).
  const needsGroup = $derived(startStep >= 3 && !(loc.query.group && /^[a-z0-9][a-z0-9-]{0,62}$/.test(loc.query.group)) && (saved?.step ?? 0) < 3 && step === 0);
  // Resume after a reload, or a link with ?group=.
  {
    const qg = loc.query.group;
    if (qg && /^[a-z0-9][a-z0-9-]{0,62}$/.test(qg) && (!saved || saved.group !== qg || saved.step < 3)) openGroup(qg, startStep >= 3 && startStep <= 4 ? startStep : 4);
    else if ((saved?.step ?? 0) >= 3) void goTo(Math.min(saved?.step ?? 3, 4));
  }

  async function refreshAssist(): Promise<void> {
    busy = true;
    try {
      await loadAssist();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }

  function reset(): void {
    step = 0;
    opening = null;
    choice = null;
    token = null;
    starter = null;
    status = null;
    groupSources = [];
    assist = null;
    choices = {};
    include = {};
    svcName = {};
    svcScheme = {};
    svcBase = {};
    twin = {};
    twinBefore = {};
    idMode = 'none';
    idName = idClaim = '';
    idFrom = 'header';
    hostsLoaded = false;
    proposal = null;
    editingDraft = false;
    preview = null;
    clearWizard();
    clearTokenMeta();
    tokenMeta = null;
  }

  // ---------------------------------------------------------------- policy assistant
  const policyCols: Column<PolicySuggestion>[] = $derived([
    { key: 'path', label: t('wiz.pol.field'), sortable: true, value: (s) => `${s.part} ${s.path}` },
    { key: 'shape', label: t('wiz.pol.shape'), hideBelow: 'md', help: 'policy.shape' },
    { key: 'distinct', label: t('wiz.pol.distinct'), sortable: true, align: 'end', hideBelow: 'sm', help: 'policy.distinct' },
    { key: 'suggestion', label: t('wiz.pol.proposal'), hideBelow: 'sm', help: 'policy.proposal' },
    { key: 'choice', label: t('wiz.pol.action'), help: 'policy.action' },
  ]);

  function setAction(id: string, picked: PolicyActionKind | 'code(alnum)'): void {
    if (picked === 'code(alnum)') {
      // spec v1.19: the code shape with digits (sanitizer.md 5.6)
      choices[id] = { action: 'code', arg: 'alnum' };
      return;
    }
    const action = picked;
    const prev = choices[id];
    const sg = suggestions.find((s) => s.id === id);
    const fromSugg = sg?.suggestion.action === action ? sg.suggestion.arg : undefined;
    const defaults: Record<PolicyActionKind, string | undefined> = { drop: undefined, keep: undefined, code: undefined, hmac: fromSugg || prev?.arg || 'id', bucket: fromSugg || prev?.arg || '0, 10, 100, 1000' };
    choices[id] = { action, arg: defaults[action] };
  }

  // Bulk actions, over the operations kept.
  const keptFields = () => (assist?.services ?? []).flatMap((s) => s.ops.filter((o) => opIncluded(s, o.op)).flatMap((o) => o.fields));
  function applyAll(): void {
    for (const f of keptFields()) choices[f.id] = safeProposal(f);
  }
  const isIdField = (f: PolicySuggestion) => f.reasonCode === 'id' || f.reasonCode === 'path_id' || /(^|[._-])(id|uuid)$|Id$|_id$/.test(f.path);
  function idsToHmac(): void {
    for (const f of keptFields()) {
      if (!isIdField(f) || f.reasonCode === 'personal_name' || f.reasonCode === 'credential' || f.reasonCode === 'trace') continue;
      choices[f.id] = f.suggestion.action === 'hmac' ? { ...f.suggestion } : { action: 'hmac', arg: 'id' };
    }
  }
  function allDrop(): void {
    for (const f of keptFields()) choices[f.id] = { action: 'drop' };
  }

  const opKey = (svc: string, op: string) => `${svc}\u0000${op}`;
  const svcIncluded = (s: AssistService) => !foldedServices.has(s.service) && include[s.service] !== false;
  function setDeclare(s: AssistService, on: boolean): void {
    include[s.service] = on;
    if (assist) rememberDeclare(assist.policyId, s.service, on);
  }
  const opIncluded = (s: AssistService, op: string) => svcIncluded(s) && include[opKey(s.service, op)] !== false;
  /** The base of an external service not declared yet: scheme + exact host, or the base typed for `{*}` / IP classes. */
  function baseOf(s: AssistService): string {
    if (s.declared || s.kind !== 'external' || !s.hostPattern) return '';
    if (s.exact) {
      const sc = svcScheme[s.service];
      return sc ? (exactBaseUrl(s.hostPattern, sc) ?? '') : '';
    }
    return (svcBase[s.service] ?? '').trim();
  }
  /** Why an included service cannot be written yet ('' when it can). */
  function blockerOf(s: AssistService): string {
    if (!svcIncluded(s) || s.declared) return '';
    const name = (svcName[s.service] ?? '').trim();
    if (!validServiceName(name)) return t('wiz.pol.svcNameNeeded', { svc: s.service });
    if (s.kind !== 'external' || !s.hostPattern) return '';
    if (s.exact && !svcScheme[s.service]) return t('wiz.pol.schemeNeeded', { host: s.hostPattern });
    if (!s.exact) {
      const b = (svcBase[s.service] ?? '').trim();
      if (!b || !checkBase(s.hostPattern, b).ok) return t('wiz.pol.baseNeeded', { host: s.hostPattern });
    }
    return '';
  }
  const idValid = $derived(
    idMode === 'none' ||
      ((idFrom === 'header' ? /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/.test(idName.trim()) : /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(idName.trim())) &&
        (idClaim.trim() === '' || /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(idClaim.trim()))),
  );
  const blockers = $derived([...(assist?.services ?? []).map(blockerOf).filter(Boolean), ...(idValid ? [] : [t('wiz.id.invalid')])]);
  const identity = $derived(
    assist && !assist.hasIdentity && idMode === 'pick' && idValid ? { from: idFrom, name: idFrom === 'header' ? idName.trim().toLowerCase() : idName.trim(), ...(idClaim.trim() ? { claim: idClaim.trim() } : {}) } : undefined,
  );

  // Only the fields of the operations kept count; the others stay as the policy has them.
  const proposed = $derived.by(() => {
    const out: Record<string, PolicyChoice> = {};
    for (const s of assist?.services ?? [])
      for (const o of s.ops) for (const f of o.fields) out[f.id] = opIncluded(s, o.op) ? (choices[f.id] ?? f.current) : f.current;
    return out;
  });
  const newDecls = $derived.by(() => {
    const out: DiffEntry[] = [];
    for (const s of assist?.services ?? []) {
      if (!svcIncluded(s)) continue;
      const name = s.declared ? s.name : (svcName[s.service] ?? '').trim();
      if (!s.declared) out.push({ change: 'added', where: `services.${name}`, to: s.kind === 'external' ? baseOf(s) || '?' : 'inbound' });
      for (const o of s.ops) if (!o.declared && opIncluded(s, o.op)) out.push({ change: 'added', where: `services.${name}.ops.${o.op}`, to: t('wiz.pol.declared') });
    }
    return out;
  });
  // Sampling: too few distinct users through the policy's rate means no rule can ever reach k. The assistant suggests
  // a rate from the traffic seen so far; asking for it is one more change of the same draft (it opens data).
  let raiseSampling = $state(true);
  const sampling = $derived(assist?.sampling);
  const suggestedBp = $derived(sampling && !sampling.enough && sampling.suggestedBp > sampling.currentBp ? sampling.suggestedBp : 0);
  const samplingBp = $derived(raiseSampling && suggestedBp ? suggestedBp : undefined);
  const bpPct = (bp: number) => fmtPct(bp / 10000, 2);
  const diff = $derived([
    ...(samplingBp && sampling ? [{ change: 'changed' as const, where: 'sampling.rate', from: bpPct(sampling.currentBp), to: bpPct(samplingBp) }] : []),
    ...newDecls,
    ...diffChoices(suggestions, currentChoices(suggestions), proposed),
    ...hostsDiff(hostsCurrent, hostsMode),
    ...(identity ? [{ change: 'added' as const, where: 'identity.subject', to: `${identity.from} ${identity.name}${identity.claim ? ` · ${identity.claim}` : ''}` }] : []),
  ]);
  // The server's classification of the preview (policy.md §7) when it gives one; the local one otherwise.
  const opens = $derived(preview?.opensValues ?? opensData(diff));
  const valueReasons = $derived(preview?.valueReasons ?? []);
  // Only the fields that really let values out in clear (keep, finer bucket): masked, dropped and code fields are not «aperti».
  const openCount = $derived(suggestions.filter((s) => opensField(s.current, proposed[s.id] ?? s.current)).length);
  const opsCount = $derived((assist?.services ?? []).reduce((n, s) => n + s.ops.filter((o) => opIncluded(s, o.op)).length, 0));

  function proposeInput() {
    const svcs = (assist?.services ?? [])
      .filter((s) => svcIncluded(s))
      .map((s) => ({
        service: s.service,
        name: s.declared ? s.name : (svcName[s.service] ?? '').trim(),
        ...(baseOf(s) ? { base: baseOf(s) } : {}),
        ops: s.ops.filter((o) => opIncluded(s, o.op)).map((o) => o.op),
      }));
    return {
      group,
      choices: suggestions.map((s) => ({ suggestionId: s.id, choice: proposed[s.id] })),
      hostsDiscovery: hostsMode,
      services: svcs,
      ...(identity ? { identity } : {}),
      ...(samplingBp ? { samplingBp } : {}),
    };
  }

  async function requestApproval(): Promise<void> {
    busy = true;
    try {
      proposal = await api.policies.propose(proposeInput());
      editingDraft = false;
      known.reload();
      toast(proposal.status === 'active' ? t('obs.applied', { v: proposal.version }) : t('wiz.review.requested'));
    } catch (e) {
      toastError(errorMessage(e));
    } finally {
      busy = false;
    }
  }

  const reasonOf = (f: PolicySuggestion) => (f.reasonCode ? tk(`wiz.reason.${f.reasonCode}`, undefined, f.reason) : f.reason);
  const samplingPct = (r: string) => fmtPct(Number(r) || 0);

  const svcCols: Column<AssistService>[] = $derived([
    { key: 'name', label: t('wiz.disc.name'), sortable: true, value: (s) => s.name || s.service },
    { key: 'calls', label: t('wiz.disc.calls'), sortable: true, align: 'end', hideBelow: 'sm' },
    { key: 'operations', label: t('wiz.disc.ops'), align: 'end', hideBelow: 'sm', value: (s) => s.ops.length },
    { key: 'twin', label: t('wiz.disc.twin') },
  ]);
</script>

<PageHeader title={t('obs.title')} description={t('obs.desc')} help="onboarding" breadcrumbs={[{ label: t('nav.onboarding') }]}>
  {#snippet actions()}
    {#if step > 0}<Button variant="ghost" onclick={reset}>{t('wiz.restart')}</Button>{/if}
  {/snippet}
</PageHeader>

{#snippet starterCard()}
  {#if starter}
    <Card id="starter" title={t('wiz.starter.title')} subtitle={t('wiz.starter.subtitle')} tone={starter.status === 'draft' ? 'accent' : 'default'}>
      <div class="stack-sm">
        <ul class="what">
          <li>{t('wiz.starter.discovery')}</li>
          <li>{t('wiz.starter.words')}</li>
          <li>{t('wiz.starter.sampling', { pct: samplingPct(samplingRate) })}</li>
        </ul>
        {#if starter.status === 'active'}
          <p class="callout ok" role="status">{t('wiz.starter.active', { v: starter.version })}</p>
        {:else if starter.status === 'draft'}
          <p>{t('wiz.starter.why', { n: starter.approvalsRequired })}</p>
          <PolicyApproval version={starter} adminLabel={t('wiz.starter.approveStart')} onchange={(v) => (starter = v)} />
        {/if}
      </div>
    </Card>
  {/if}
{/snippet}

<div class="stack">
  <Card>
    <Stepper steps={stepDefs} current={step} onselect={(i) => (i >= 3 ? goTo(i) : (step = i))} />
  </Card>

  <NewHostsHint />

  {#if loadError}<Loading error={loadError} />{/if}
  {#if opening !== null && step !== opening}
    {#if busy}
      <Loading label={t('fix4.wiz.stepLoading', { group })} lines={3} />
    {:else if loadError}
      <p class="callout" role="status" data-testid="step-open-failed">{t('fix4.wiz.stepFailed')} <button type="button" class="link-btn" onclick={reset}>{t('fix4.wiz.backStart')}</button></p>
    {/if}
  {/if}

  <!-- ============================================================ 1 -->
  {#if step === 0}
    {#if needsGroup}<p class="callout warn" role="status" data-testid="needs-group">{t('fix4.wiz.pickGroup')}</p>{/if}
    <Card title={t('obs.connect.title')} subtitle={t('obs.connect.subtitle')}>
      {#snippet actions()}<InfoTip id="wiz.choice" />{/snippet}
      <!-- svelte-ignore a11y_interactive_supports_focus -->
      <div class="cards" role="radiogroup" aria-label={t('wiz.source.title')} onkeydown={cardKeys}>
        {#each CARDS as c, ci (c.id)}
          <button type="button" role="radio" aria-checked={choice === c.id} tabindex={choice === c.id || (!choice && ci === 0) ? 0 : -1} class="src" class:sel={choice === c.id} onclick={() => (choice = c.id)}>
            <span class="ico"><Icon name={c.icon} size={22} /></span>
            <b>{c.title ?? (c.titleKey ? t(c.titleKey) : '')}</b>
            <span class="muted">{t(c.descKey)}</span>
            <span class="req subtle">{c.req ?? (c.reqKey ? t(c.reqKey) : '')}</span>
            {#if choice === c.id}<span class="tick"><Icon name="check" size={16} /></span>{/if}
          </button>
        {/each}
      </div>
      <div class="stack-sm group">
        <Field label={t('wiz.source.services')} help="wiz.services" hint={t('wiz.source.servicesHint')} error={namesValid ? '' : t('wiz.source.servicesInvalid')}>
          {#snippet children({ id, describedby })}
            <input {id} bind:value={svcNames} placeholder={t('wiz.source.servicesPlaceholder')} aria-describedby={describedby} aria-invalid={namesValid ? undefined : 'true'} spellcheck="false" autocomplete="off" />
          {/snippet}
        </Field>
        <Field label={t('wiz.source.group')} help="wiz.group" hint={t('wiz.source.groupHint')} error={group === '' || groupValid ? '' : t('wiz.source.groupInvalid')}>
          {#snippet children({ id, describedby })}
            <input {id} bind:value={group} placeholder={groupPlaceholder} aria-describedby={describedby} aria-invalid={group === '' || groupValid ? undefined : 'true'} spellcheck="false" autocomplete="off" />
          {/snippet}
        </Field>
        {#if group === '' && groupSuggested}
          <div><Button size="sm" variant="ghost" onclick={() => (group = groupSuggested)}>{t('wiz.source.groupUse', { name: groupSuggested })}</Button></div>
        {/if}
        {#if groupExists}<p class="callout warn" role="status">{t('wiz.source.groupExists', { group })}</p>{/if}
        <details class="adv">
          <summary>{t('obs.advanced.summary')}</summary>
          <Field label={t('obs.sampling.label')} help="obs.sampling" hint={t('obs.sampling.hint')}>
            {#snippet children({ id, describedby })}
              <select {id} bind:value={samplingRate} aria-describedby={describedby}>
                <option value="0.1">{t('obs.sampling.default')}</option>
                <option value="0.25">{t('obs.sampling.mid')}</option>
                <option value="1">{t('obs.sampling.all')}</option>
                <option value="0.05">{t('obs.sampling.low')}</option>
              </select>
            {/snippet}
          </Field>
        </details>
      </div>
    </Card>
    {#if tokenMeta && !token}
      <Card title={t('wiz.tokenMeta.title')} tone="accent">
        <div class="stack-sm" data-testid="token-meta">
          <p>{metaExpired ? t('wiz.tokenMeta.expired', { group: tokenMeta.group, at: clockTime(tokenMeta.createdAt), until: clockTime(tokenMeta.expiresAt) }) : t('wiz.tokenMeta.active', { group: tokenMeta.group, at: clockTime(tokenMeta.createdAt), until: clockTime(tokenMeta.expiresAt) })}</p>
          <p class="subtle">{t('wiz.tokenMeta.why')}</p>
          <div class="row">
            <Button variant="primary" icon="refresh" loading={busy} denied={!can('sources.manage')} onclick={() => regenerate()}>{t('wiz.tokenMeta.regenerate')}</Button>
            <Button variant="ghost" onclick={() => { clearTokenMeta(); tokenMeta = null; }}>{t('wiz.tokenMeta.dismiss')}</Button>
          </div>
        </div>
      </Card>
    {/if}
    <div class="nav">
      <span></span>
      <Button variant="primary" icon="arrowRight" disabled={!choice || !groupValid || !namesValid} denied={!can('sources.manage')} loading={busy} onclick={createToken}>{t('wiz.source.next')}</Button>
    </div>
    {#if knownGroups.length}
      <Card title={t('wiz.resume.title')} subtitle={t('wiz.resume.subtitle')}>
        <div class="row resume">
          {#each knownGroups as g (g)}
            <Button size="sm" icon="arrowRight" loading={busy && group === g} onclick={() => openGroup(g, 4)}>{t('wiz.resume.open', { group: g })}</Button>
          {/each}
        </div>
      </Card>
    {/if}
  {/if}

  <!-- ============================================================ 2 -->
  {#if step === 1 && token}
    <Card title={t('wiz.install.title')} subtitle={t('wiz.install.subtitle')}>
      <div class="stack">
        <div class="row tok">
          <div class="grow">
            <span class="subtle">{t('wiz.install.token')}</span> <InfoTip id="wiz.token" />
            <div class="mono tokval" data-testid="token">{token.token}</div>
          </div>
          <Badge tone="warning">{t('wiz.install.expires', { at: fmtDate(token.expiresAt) })}</Badge>
        </div>
        <p class="row subtle" data-testid="token-times">
          <span>{t('wiz.install.times', { at: clockTime(token.createdAt ?? token.expiresAt), until: clockTime(token.expiresAt) })}</span>
          <Button size="sm" variant="ghost" icon="refresh" loading={busy} denied={!can('sources.manage')} onclick={() => regenerate()}>{t('wiz.tokenMeta.regenerate')}</Button>
        </p>
        <p class="callout">{t('wiz.install.once')}</p>
        <p class="subtle">{t('wiz.install.reload')}</p>
        <p class="callout">{t('wiz.install.hmac')}</p>
        {#if !needsApproval}<p class="callout ok" role="status" data-testid="no-policy">{t('obs.install.noPolicy')}</p>{/if}
        {#if names.length === 0}<p class="callout" role="status">{t('wiz.install.serviceName')}</p>{/if}
        {#each token.snippets as sn, i (i)}
          <CodeBlock code={sn.text} title={sn.title} language={sn.language} />
        {/each}
      </div>
    </Card>
    {#if needsApproval}{@render starterCard()}{/if}
    <div class="nav">
      <Button icon="arrowLeft" onclick={() => (step = 0)}>{t('common.back')}</Button>
      <Button variant="primary" icon="arrowRight" onclick={() => goTo(2)}>{t('wiz.install.next')}</Button>
    </div>
  {/if}

  <!-- ============================================================ 3 -->
  {#if step === 2}
    {#if needsApproval}{@render starterCard()}{/if}
    {#if openingDrafts.length}<ApprovalNextStep drafts={openingDrafts} {required} capturing={activeVersion?.version} facts={statesFacts(groupPolicies, [group], groupRules.data ?? null)} onchange={() => known.reload()} />{/if}
    <Card title={t('obs.listen.title')} subtitle={t('obs.listen.subtitle')}>
      <ol class="checks" aria-live="polite">
        {#each checks as c (c.id)}
          <li class={c.state}>
            <span class="mark" aria-hidden="true">
              {#if c.state === 'done'}<Icon name="check" size={16} />{:else if c.state === 'problem'}<Icon name="alert" size={16} />{:else if c.state === 'active'}<span class="pulse"></span>{/if}
            </span>
            <div>
              <b>{c.label}</b>
              <div class="subtle">{c.detail}</div>
            </div>
            <span class="sr-only">{t(`wiz.state.${c.state}` as 'wiz.state.done')}</span>
          </li>
        {/each}
      </ol>
      {#if status?.problems.length}
        <div class="stack-sm probs">
          {#each status.problems as p, i (i)}
            {@const pt = problemText(p)}
            <div class="callout warn" role="alert">
              <b>{pt.title}</b>
              {#if pt.hint}<div class="subtle">{t('wiz.wait.how')} {pt.hint}</div>{/if}
              {#if (p.code === 'no_policy' || p.code === 'policy_rejected') && needsApproval}<div><a href="#starter">{t('wiz.wait.approveAbove')}</a></div>{/if}
            </div>
          {/each}
        </div>
      {/if}
      {#if connected.length && (status?.firstEvents ?? 0) < eventsGoal}
        <p class="callout ok" role="status">{t('wiz.wait.connected', { n: connected.length, names: [...new Set(connected.map((c) => c.serviceName))].join(', ') })}</p>
      {/if}
    </Card>

    {#if observe}
      <Card title={t('obs.masked.title')} subtitle={t('obs.listen.events', { n: fmtNum(observe.events) })} tone={observe.phase === 'masked' ? 'accent' : 'default'}>
        {#snippet actions()}<InfoTip id="obs.masked" />{/snippet}
        <div class="stack-sm" data-testid="observe" aria-live="polite">
          {#if observe.phase === 'listening'}
            <p class="callout" role="status">{observe.dueAt ? t('obs.listen.waiting', { min: fmtNum(observe.minEvents), due: clockTime(observe.dueAt) }) : t('obs.listen.waitingNoDue', { min: fmtNum(observe.minEvents) })}</p>
            {#if !observe.enabled}<p class="callout warn" role="status">{t('obs.listen.disabled')}</p>{/if}
          {:else if observe.phase === 'masked'}
            <p class="callout ok" role="status" data-testid="observe-active">{t('obs.listen.masked', { at: clockTime(observe.observeActivatedAt ?? ''), v: observe.observeVersion ?? 0 })}</p>
          {:else if observe.phase === 'managed'}
            <p class="callout" role="status">{t('obs.listen.managed')}</p>
          {:else if observe.phase === 'waiting_approval'}
            <p class="callout warn" role="status">{t('obs.listen.approval')}</p>
          {:else}
            <p class="callout warn" role="status">{t('obs.listen.noPolicy')}</p>
          {/if}
          {#if observe.masked.length}
            <ul class="masked" data-testid="masked">
              {#each uniqBy(observe.masked, (m) => `${m.service}\u0000${m.op ?? ''}\u0000${m.part}\u0000${m.kind}\u0000${m.field}`) as m, i (i)}
                <li><Icon name="lock" size={14} /> {t('obs.masked.item', { field: maskedField(m), part: maskedPart(m), where: m.op || m.service, domain: m.domain })}</li>
              {/each}
            </ul>
          {:else if observe.phase === 'masked' || observe.phase === 'listening'}
            <p class="subtle">{t('obs.masked.none')}</p>
          {/if}
          {#if observe.identity}
            <p class="subtle">{observe.identity.claim ? t('obs.identity.jwt', { claim: observe.identity.claim, name: observe.identity.name }) : t('obs.identity.header', { name: observe.identity.name })}</p>
          {/if}
          {#if observe.enabled}
            <div class="row-tight" data-testid="observe-auto">
              <Switch checked={observe.auto} label={t('obs.auto.label')} disabled={!can('policy.propose') || autoBusy} onchange={(v) => setObserveAuto(v)} />
              <InfoTip id="obs.auto" />
            </div>
            {#if !observe.auto}<p class="subtle">{t('obs.auto.off')}</p>{/if}
          {/if}
        </div>
      </Card>

      <Card title={t('id.title')}>
        <IdentityControl groups={[group]} status={observe} onchange={() => { known.reload(); void loadObserve(); }} />
      </Card>

      <Card title={t('obs.services.title')} subtitle={`${t('obs.listen.services', { n: ownServices.length })} · ${t('obs.listen.hosts', { n: extServices.length })}`}>
        {#if observe.services.length === 0}
          <p class="subtle">{t('obs.services.none')}</p>
        {:else}
          <ul class="found">
            {#each uniqBy(observe.services, (s) => `${s.kind}\u0000${s.service}`) as s, i (i)}
              <li><Badge tone={s.kind === 'inbound' ? 'accent' : 'info'}>{t(s.kind === 'inbound' ? 'wiz.disc.own' : 'wiz.disc.external')}</Badge> <b class="mono">{s.service}</b> <span class="subtle">{t('obs.services.calls', { n: fmtNum(s.calls) })}</span></li>
            {/each}
          </ul>
        {/if}
        {#if obsSuggestedBp && obsSampling}
          <div class="stack-sm samp">
            <p class="subtle">{t('obs.sampling.raiseWhy', { n: fmtNum(obsSampling.sampledSubjects), need: fmtNum(obsSampling.targetSubjects), k: obsSampling.kMin })}</p>
            <div><Button size="sm" icon="arrowRight" loading={busy} denied={!can('policy.propose')} onclick={raiseObserveSampling}>{t('obs.sampling.raise', { rate: fmtPct(obsSuggestedBp / 10000, 2) })}</Button></div>
          </div>
        {/if}
      </Card>
    {/if}

    <div class="nav">
      <Button icon="arrowLeft" onclick={() => (step = 1)}>{t('common.back')}</Button>
      <div class="row navr">
        <Button variant="ghost" loading={busy} onclick={() => goTo(3)} title={t('obs.advancedHint')}>{t('obs.advanced')}</Button>
        <Button variant="primary" icon="check" href={href('/')}>{t('obs.done')}</Button>
      </div>
    </div>
    <p class="subtle advhint">{t('obs.advancedHint')}</p>
  {/if}

  <!-- The advanced steps: a page error (unexpected data) shows a message and a way out, never a blank page (M2). -->
  <svelte:boundary onerror={(e) => console.error('onboarding step', e)}>
  {#snippet failed(error, retry)}
    <div class="callout danger" role="alert" data-testid="step-failed">
      <p>{t('fix4.renderFailed', { error: error instanceof Error ? error.message : String(error) })}</p>
      <div class="row">
        <Button size="sm" icon="refresh" onclick={() => { retry(); void refreshAssist(); }}>{t('fix4.renderRetry')}</Button>
        <Button size="sm" variant="ghost" onclick={() => { reset(); retry(); }}>{t('fix4.wiz.backStart')}</Button>
      </div>
    </div>
  {/snippet}
  <!-- ============================================================ 4 -->
  {#if step === 3 && assist}
    <Card title={t('wiz.disc.title')} subtitle={t('wiz.disc.subtitleGroup', { group })} flush>
      {#if assist.services.length === 0}<div class="pad"><p class="callout warn" role="status">{t('wiz.pol.noTraffic', { n: assist.minCalls })}</p></div>{/if}
      <Table rows={shownServices} columns={svcCols} rowKey={(s) => s.service} caption={t('wiz.disc.title')}>
        {#snippet cell(s, col)}
          {#if col.key === 'name'}
            <b>{s.declared ? s.name : s.service}</b> <Badge tone={s.kind === 'own' ? 'accent' : 'info'}>{t(`wiz.disc.${s.kind}` as 'wiz.disc.own')}</Badge>
            {#if s.declared}<Badge>{t('wiz.pol.inPolicy')}</Badge>{/if}
            {#if s.hostPattern && can('hosts.twin')}<div class="subtle"><a href={href('/hosts', {}, { q: s.hostPattern })}>{t('svc.hostGroup')}</a></div>{/if}
            <div class="subtle m-only">{t('wiz.disc.callsOps', { calls: fmtNum(s.calls), ops: s.ops.length })}</div>
          {:else if col.key === 'calls'}
            <span class="num">{fmtNum(s.calls)}</span>
          {:else if col.key === 'operations'}
            <span class="num">{s.ops.length}</span>
          {:else if s.kind === 'external'}
            <label class="chk"><input type="checkbox" bind:checked={twin[twinKey(s)]} disabled={!can('sources.manage')} /> {t('wiz.disc.twinIt')}</label>
          {:else}
            <span class="subtle">—</span>
          {/if}
        {/snippet}
      </Table>
    </Card>
    <div class="nav">
      <Button icon="arrowLeft" onclick={() => (step = 2)} disabled={!token}>{t('common.back')}</Button>
      <Button variant="primary" icon="arrowRight" loading={busy} onclick={() => goTo(4)}>{t('wiz.disc.next')}</Button>
    </div>
  {/if}

  <!-- ============================================================ 5 -->
  {#if step === 4 && assist}
    <Card title={t('wiz.pol.title')} subtitle={t('wiz.pol.subtitle')}>
      {#snippet actions()}<Button size="sm" variant="ghost" icon="refresh" loading={busy} onclick={refreshAssist}>{t('wiz.pol.refresh')}</Button>{/snippet}
      <div class="stack-sm">
        {#if draftVersion}
          <p class="callout" role="status" data-testid="draft-banner"><b>{t('wiz.draft.accumulate', { v: draftVersion.version })}</b> {t('wiz.draft.accumulateWhy', { v: draftVersion.version })} <a href={href('/sources', {}, { tab: 'policy', draft: `${draftVersion.policyId}@${draftVersion.version}` })}>{t('wiz.draft.see')}</a></p>
        {:else}
          <p class="callout" role="status">{t('wiz.draft.once')}</p>
        {/if}
        <p class="callout">{t('wiz.pol.never')}</p>
        <p class="subtle">{t('wiz.pol.legend')}</p>
        {#if assist.services.length === 0}
          <p class="callout warn" role="status">{t('wiz.pol.noTraffic', { n: assist.minCalls })}</p>
        {:else if !assist.ready}
          <p class="callout warn" role="status">{t('wiz.pol.needMore', { n: assist.needCalls, min: assist.minCalls })}</p>
        {:else}
          <p class="callout ok" role="status">{t('wiz.pol.enough', { min: assist.minCalls })}</p>
        {/if}
        <div class="row bulk" role="group" aria-label={t('wiz.pol.bulk')}>
          <Button size="sm" icon="check" onclick={applyAll}>{t('wiz.pol.applyAll')}</Button>
          <Button size="sm" icon="lock" onclick={idsToHmac}>{t('wiz.pol.idsHmac')}</Button>
          <Button size="sm" variant="ghost" onclick={allDrop}>{t('wiz.pol.allDrop')}</Button>
        </div>
      </div>
    </Card>

    <Card title={t('wiz.id.title')} subtitle={t('wiz.id.subtitle')}>
      {#snippet actions()}<InfoTip id="wiz.identity" />{/snippet}
      {#if assist.hasIdentity}
        <p class="callout ok" role="status">{t('wiz.id.already')}</p>
      {:else}
        <div class="stack-sm">
          <label class="mode" class:sel={idMode === 'none'}><input type="radio" name="id-mode" value="none" bind:group={idMode} /> <span>{t('wiz.id.none')}<span class="subtle block">{t('wiz.id.noneDesc')}</span></span></label>
          {#each uniqBy(assist.identityCandidates, (c) => `${c.from}\u0000${c.name}`) as c, i (i)}
            <label class="mode" class:sel={idMode === 'pick' && idFrom === c.from && idName === c.name}>
              <input type="radio" name="id-mode" checked={idMode === 'pick' && idFrom === c.from && idName === c.name} onchange={() => { idMode = 'pick'; idFrom = c.from; idName = c.name; idClaim = c.claim ?? (c.jwt ? 'sub' : ''); }} />
              <span><b class="mono">{c.from} {c.name}</b>{#if c.jwt} <Badge tone="accent">JWT → sub</Badge>{/if}<span class="subtle block">{t(c.jwt ? 'wiz.id.candJwt' : 'wiz.id.cand', { calls: fmtNum(c.calls), distinct: fmtNum(c.distinct) })}</span></span>
            </label>
          {/each}
          <label class="mode" class:sel={idMode === 'pick' && !assist.identityCandidates.some((c) => c.from === idFrom && c.name === idName)}>
            <input type="radio" name="id-mode" checked={idMode === 'pick' && !assist.identityCandidates.some((c) => c.from === idFrom && c.name === idName)} onchange={() => { idMode = 'pick'; idName = ''; idClaim = ''; }} />
            <span>{t('wiz.id.custom')}</span>
          </label>
          {#if idMode === 'pick'}
            <div class="row idrow">
              <Field label={t('wiz.id.from')}>
                {#snippet children({ id })}<select {id} bind:value={idFrom}><option value="header">header</option><option value="cookie">cookie</option></select>{/snippet}
              </Field>
              <Field label={t('wiz.id.name')} hint={t('wiz.id.nameHint')}>
                {#snippet children({ id, describedby })}<input {id} bind:value={idName} aria-describedby={describedby} spellcheck="false" autocomplete="off" placeholder="authorization" />{/snippet}
              </Field>
              <Field label={t('wiz.id.claim')} hint={t('wiz.id.claimHint')}>
                {#snippet children({ id, describedby })}<input {id} bind:value={idClaim} aria-describedby={describedby} spellcheck="false" autocomplete="off" placeholder="sub" />{/snippet}
              </Field>
            </div>
          {/if}
        </div>
      {/if}
    </Card>

    {#if sampling}
      <Card title={t('wiz.samp.title')} subtitle={t('wiz.samp.subtitle')}>
        <div class="stack-sm">
          {#if sampling.source === 'no_identity'}
            <p class="subtle">{t('wiz.samp.rateOnly', { rate: bpPct(sampling.currentBp), k: sampling.kMin })}</p>
          {:else}
            <p class="subtle">{t('wiz.samp.current', { rate: bpPct(sampling.currentBp), n: fmtNum(sampling.sampledSubjects), k: sampling.kMin, approx: '' })}</p>
          {/if}
          {#if sampling.source === 'no_identity'}
            <p class="callout warn" role="status" data-testid="samp-no-identity">{t('wiz.samp.noIdentity')}</p>
          {:else if sampling.enough}
            <p class="callout ok" role="status">{t('wiz.samp.enough', { n: fmtNum(sampling.sampledSubjects), k: sampling.kMin })}</p>
          {:else if sampling.sampledSubjects === 0}
            <p class="callout warn" role="status">{t('wiz.samp.none')}</p>
          {:else if suggestedBp}
            <p class="callout warn" role="status">{t('wiz.samp.few', { n: fmtNum(sampling.sampledSubjects), need: fmtNum(sampling.targetSubjects), k: sampling.kMin, pop: fmtNum(sampling.populationEstimate), rate: bpPct(suggestedBp), target: fmtNum(Math.round((sampling.sampledSubjects * suggestedBp) / sampling.currentBp)) })}</p>
            <label class="chk"><input type="checkbox" bind:checked={raiseSampling} /> {t('wiz.samp.raise', { rate: bpPct(suggestedBp) })}</label>
            {#if raiseSampling}<p class="subtle">{t('wiz.samp.opens')}</p>{/if}
          {:else}
            <p class="callout warn" role="status">{t('wiz.samp.waitOnly', { n: fmtNum(sampling.sampledSubjects), need: fmtNum(sampling.targetSubjects), k: sampling.kMin, pop: fmtNum(sampling.populationEstimate) })}</p>
          {/if}
        </div>
      </Card>
    {/if}

    {#each shownServices as s (s.service)}
      <Card title={s.declared ? s.name : s.service} subtitle={t(s.kind === 'own' ? 'wiz.pol.svcOwn' : 'wiz.pol.svcExt', { calls: fmtNum(s.calls), ops: s.ops.length })} flush>
        {#snippet actions()}
          {#if s.declared}<Badge>{t('wiz.pol.inPolicy')}</Badge>{/if}
          {#if s.stale}<Badge tone="warning" title={t('wiz.pol.staleTip')}>{t('wiz.pol.stale')}</Badge>{/if}
          <label class="chk"><input type="checkbox" checked={svcIncluded(s)} onchange={(e) => setDeclare(s, e.currentTarget.checked)} /> {t('wiz.pol.includeSvc')}</label>
        {/snippet}
        {#if s.mergedPatterns?.length}<p class="pad subtle merged">{t('wiz.pol.merged', { hosts: s.mergedPatterns.join(', ') })}</p>{/if}
        {#if svcIncluded(s) && !s.declared}
          <div class="pad decl stack-sm">
            <Field label={t('wiz.pol.svcName')} hint={t('wiz.pol.svcNameHint')} error={validServiceName((svcName[s.service] ?? '').trim()) ? '' : t('err.invalid_service')}>
              {#snippet children({ id, describedby })}
                <input {id} bind:value={svcName[s.service]} aria-describedby={describedby} spellcheck="false" autocomplete="off" />
              {/snippet}
            </Field>
            {#if s.kind === 'external' && s.hostPattern}
              {#if s.exact}
                <fieldset class="scheme">
                  <legend>{t('hosts.twin.scheme')}</legend>
                  <div class="row">
                    {#each ['http', 'https'] as const as sc (sc)}
                      <label class="chk"><input type="radio" name={`scheme-${s.service}`} value={sc} bind:group={svcScheme[s.service]} /> <span class="mono">{sc}://{s.hostPattern}</span></label>
                    {/each}
                  </div>
                  <p class="subtle">{t('hosts.twin.schemeHint')}</p>
                </fieldset>
              {:else}
                <Field label={t('hosts.twin.base')} help="hosts.base" hint={t('wiz.pol.baseHint', { host: s.hostPattern })}>
                  {#snippet children({ id, describedby })}
                    <input {id} bind:value={svcBase[s.service]} aria-describedby={describedby} spellcheck="false" autocomplete="off" inputmode="url" />
                  {/snippet}
                </Field>
              {/if}
            {/if}
          </div>
        {/if}
        {#if svcIncluded(s)}
          {#each s.ops as o (o.op)}
            <div class="op" class:off={!opIncluded(s, o.op)}>
              <div class="row ophead pad">
                <label class="chk"><input type="checkbox" bind:checked={include[opKey(s.service, o.op)]} /> <b class="mono">{o.op}</b></label>
                {#if o.declared}<Badge>{t('wiz.pol.inPolicy')}</Badge>{/if}
                <span class="subtle">{t('wiz.pol.opCalls', { n: fmtNum(o.calls) })}</span>
                {#if o.needCalls > 0}<Badge tone="warning">{t('wiz.pol.opNeed', { n: o.needCalls })}</Badge>{/if}
                {#if o.rawOps.length && o.rawOps.some((r) => r !== o.op)}<span class="subtle mono raw" title={o.rawOps.join('\n')}>{t('wiz.pol.fromRaw', { raw: o.rawOps[0] })}</span>{/if}
              </div>
              {#if opIncluded(s, o.op)}
                {#if o.fields.length === 0}
                  <p class="pad subtle">{t('wiz.pol.noFields')}</p>
                {:else}
                  <Table rows={o.fields} columns={policyCols} rowKey={(f) => f.id} caption={`${s.service} ${o.op}`}>
                    {#snippet cell(f, col)}
                      {#if col.key === 'path'}
                        <code>{f.path}</code>
                        <div class="subtle">{tk(`wiz.part.${f.part}`, undefined, f.part)}</div>
                        <div class="subtle m-only">{f.shape} · {fmtNum(f.distinct)} / {fmtNum(f.observed)}</div>
                      {:else if col.key === 'shape'}
                        <span class="muted">{f.shape}</span>
                        <div class="subtle">{reasonOf(f)}</div>
                      {:else if col.key === 'distinct'}
                        <span class="num">{fmtNum(f.distinct)}</span><span class="subtle"> / {fmtNum(f.observed)}</span>
                      {:else if col.key === 'suggestion'}
                        <Badge tone={f.suggestion.action === 'drop' ? 'neutral' : 'accent'}>{formatChoice(f.suggestion)}</Badge>
                      {:else}
                        {@const c = choices[f.id]}
                        <div class="edit">
                          <select aria-label={t('wiz.pol.actionFor', { field: f.path })} value={c.action === 'code' && c.arg === 'alnum' ? 'code(alnum)' : c.action} onchange={(e) => setAction(f.id, e.currentTarget.value as PolicyActionKind | 'code(alnum)')}>
                            <option value="drop">drop</option>
                            <option value="keep">keep</option>
                            <option value="code">code</option>
                            <option value="code(alnum)" title={t('code.alnum.tip')}>{t('code.alnum.option')}</option>
                            <option value="hmac">hmac</option>
                            <option value="bucket">bucket</option>
                          </select>
                          {#if c.action === 'hmac' || c.action === 'bucket'}
                            <input
                              aria-label={c.action === 'hmac' ? t('wiz.pol.domain') : t('wiz.pol.buckets')}
                              placeholder={c.action === 'hmac' ? t('wiz.pol.domain') : t('wiz.pol.buckets')}
                              value={c.arg ?? ''}
                              oninput={(e) => (choices[f.id] = { action: c.action, arg: e.currentTarget.value })}
                            />
                          {/if}
                          {#if !sameChoice(c, f.current)}<Badge tone={c.action === 'drop' ? 'success' : c.action === 'hmac' || c.action === 'code' ? 'info' : 'warning'}>{c.action === 'drop' ? t('wiz.pol.closes') : c.action === 'hmac' ? t('obs.field.masks') : c.action === 'code' ? t('code.field.codes') : t('wiz.pol.opens')}</Badge>{/if}
                        </div>
                      {/if}
                    {/snippet}
                  </Table>
                {/if}
              {/if}
            </div>
          {/each}
        {/if}
      </Card>
    {/each}

    <Card title={t('hosts.disc.title')} subtitle={t('hosts.disc.subtitle')}>
      {#snippet actions()}<InfoTip id="hosts.discovery" />{/snippet}
      <div class="stack-sm">
        <div class="modes" role="radiogroup" aria-label={t('hosts.disc.title')}>
          {#each ['auto', 'off'] as const as m (m)}
            <label class="mode" class:sel={hostsMode === m}>
              <input type="radio" name="hosts-discovery" value={m} bind:group={hostsMode} />
              <span><b class="mono">hosts.discovery: {m}</b> {#if hostsCurrent === m}<Badge>{t('hosts.disc.current')}</Badge>{/if}<span class="subtle block">{tk(`hosts.disc.${m}.desc`)}</span></span>
            </label>
          {/each}
        </div>
        {#if hostsMode !== hostsCurrent}
          <p class="callout {hostsMode === 'auto' ? 'warn' : ''}" role="status">{hostsMode === 'auto' ? t('hosts.disc.opens') : t('hosts.disc.closes')}</p>
        {/if}
        <p class="subtle"><a href={href('/hosts')}>{t('hosts.disc.see')}</a></p>
      </div>
    </Card>

    {#if blockers.length}
      <ul class="callout warn blockers" role="status">{#each blockers as b (b)}<li>{b}</li>{/each}</ul>
    {/if}
    <div class="nav">
      <Button icon="arrowLeft" onclick={() => (step = 3)}>{t('common.back')}</Button>
      <Button variant="primary" icon="arrowRight" disabled={blockers.length > 0 || opsCount === 0} onclick={() => goTo(5)}>{t('wiz.pol.nextOps', { ops: opsCount, n: openCount })}</Button>
    </div>
  {/if}

  <!-- ============================================================ 6 -->
  {#if step === 5}
    <Card title={t('wiz.review.title')} subtitle={t('wiz.review.subtitle')}>
      <div class="stack">
        {#if diff.length === 0}
          <p class="callout warn">{t('wiz.review.nochange')}</p>
        {:else}
          <ul class="changes">
            {#each diff as d, i (i)}
              <li>
                <Badge tone={d.change === 'removed' ? 'success' : 'warning'}>{tk(`diff.${d.change}`, undefined, d.change)}</Badge>
                <span class="grow">{d.where}</span>
                {#if d.from || d.to}<code>{d.from ?? ''}{d.from ? ' → ' : ''}{d.to ?? ''}</code>{/if}
              </li>
            {/each}
          </ul>
          {#if preview}<DiffView before={preview.before} after={preview.after} format="yaml" />{/if}
        {/if}
      </div>
    </Card>

    <Card title={t('wiz.two.title')} tone={opens ? 'accent' : 'default'}>
      {#snippet actions()}<InfoTip id="obs.classify" />{/snippet}
      <div class="stack">
        <p class="callout {opens ? 'warn' : 'ok'}" role="status" data-testid="classify">{opens ? t('obs.class.opens') : t('obs.class.safe')}</p>
        {#if opens && valueReasons.length}
          <div class="subtle">{t('obs.class.why')} <ul class="reasons">{#each valueReasons as r, i (i)}<li>{reasonText(r)} <code>{r.where}</code></li>{/each}</ul></div>
        {/if}
        {#if opens}<p>{t('obs.class.opensN', { n: required })}</p>{/if}
        {#if opens}
          <ol class="flow">
            <li><b>{t('wiz.two.s1')}</b><span class="subtle">{t('wiz.two.s1d')}</span></li>
            <li><b>{t('wiz.two.s2')}</b><span class="subtle">{t('wiz.two.s2d')}</span></li>
            {#if required === 2}<li class="distinct"><b>{t('wiz.two.s3')}</b><span class="subtle">{t('wiz.two.s3d')}</span></li>{/if}
            <li><b>{t('wiz.two.s4')}</b><span class="subtle">{t('wiz.two.s4d')}</span></li>
          </ol>
        {/if}
        {#if !proposal && opens && !can('override.admin')}<ApproverHelp {required} {group} />{/if}
        {#if editingDraft && proposal}
          <p class="callout warn" role="status">{t('wiz.draft.editing', { v: proposal.version })}</p>
        {:else if proposal}
          <div class="callout ok" role="status"><b>{t('wiz.review.done', { v: proposal.version })}</b></div>
          {#if proposal.status === 'active'}
            <p class="callout ok" role="status">{t('wiz.review.active', { v: proposal.version })}</p>
          {:else}
            <PolicyApproval version={proposal} onchange={(v) => { if (v.status === 'withdrawn') { proposal = null; editingDraft = false; known.reload(); } else proposal = v; }} />
          {/if}
        {/if}
      </div>
    </Card>

    <div class="nav">
      <Button icon="arrowLeft" onclick={() => { if (proposal) editingDraft = true; step = 4; }} disabled={!!proposal && !editingDraft && (proposal.status !== 'draft' || proposal.approvals.length > 0)} title={proposal && proposal.approvals.length > 0 ? t('wiz.draft.approved') : undefined}>{proposal && proposal.status === 'draft' && !editingDraft ? t('wiz.draft.edit') : t('common.back')}</Button>
      {#if proposal && !editingDraft}
        <Button variant="primary" href="#/sources?tab=policy">{t('wiz.review.goPolicies')}</Button>
      {:else}
        <Button variant="primary" icon="lock" loading={busy} disabled={diff.length === 0} denied={!can('policy.propose')} onclick={requestApproval}>
          {proposal ? t('wiz.draft.update', { v: proposal.version }) : !opens ? t('obs.apply') : required === 2 ? t('wiz.review.requestTwo') : t('wiz.review.request')}
        </Button>
      {/if}
    </div>
  {/if}
  </svelte:boundary>
</div>

<style>
  .cards { display: grid; gap: var(--s-3); grid-template-columns: repeat(auto-fill, minmax(min(100%, 14.5rem), 1fr)); }
  .src { position: relative; text-align: left; display: flex; flex-direction: column; gap: var(--s-1); font: inherit; color: var(--fg); background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--r-md); padding: var(--s-4); cursor: pointer; }
  .src:hover { border-color: var(--accent); }
  .src.sel { border-color: var(--accent); background: var(--accent-soft); box-shadow: 0 0 0 1px var(--accent); }
  .ico { display: grid; place-items: center; width: 2.4rem; height: 2.4rem; border-radius: var(--r-sm); background: var(--surface-3); color: var(--accent); margin-bottom: var(--s-1); }
  .src b { font-size: 1.02rem; }
  .req { margin-top: var(--s-1); font-family: var(--font-mono); font-size: 0.76rem; }
  .tick { position: absolute; top: var(--s-3); right: var(--s-3); color: var(--accent); }
  .group { margin-top: var(--s-5); max-width: 26rem; }
  .nav { display: flex; justify-content: space-between; gap: var(--s-3); flex-wrap: wrap; }
  .tok { align-items: flex-end; }
  .tokval { font-size: 1rem; word-break: break-all; padding: var(--s-2) var(--s-3); background: var(--surface-2); border-radius: var(--r-sm); border: 1px dashed var(--border-strong); }
  .checks { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-3); }
  .checks li { display: flex; gap: var(--s-3); align-items: flex-start; }
  .mark { flex: none; display: grid; place-items: center; width: 1.7rem; height: 1.7rem; border-radius: 50%; border: 2px solid var(--border-strong); color: var(--fg-subtle); }
  .done .mark { background: var(--success); border-color: var(--success); color: var(--surface); }
  .active .mark { border-color: var(--accent); }
  .problem .mark { background: var(--warning); border-color: var(--warning); color: var(--surface); }
  .pulse { width: 0.6rem; height: 0.6rem; border-radius: 50%; background: var(--accent); animation: pulse 1.1s ease-in-out infinite; }
  @keyframes pulse { 50% { transform: scale(0.5); opacity: 0.5; } }
  .pending b { color: var(--fg-subtle); }
  .probs { margin-top: var(--s-4); }
  .checks + .callout { margin-top: var(--s-4); }
  .pad { padding: 0 var(--s-4); margin-bottom: var(--s-3); }
  @media (min-width: 901px) { .m-only { display: none; } }
  .chk { display: inline-flex; gap: var(--s-2); align-items: center; font-weight: 500; }
  .edit { display: flex; gap: var(--s-2); align-items: center; flex-wrap: wrap; min-width: 11rem; }
  .edit select { width: 6.5rem; }
  .edit input { width: 8.5rem; }
  .changes { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-2); }
  .changes li { display: flex; gap: var(--s-3); align-items: center; flex-wrap: wrap; padding: var(--s-2) var(--s-3); background: var(--surface-2); border-radius: var(--r-sm); }
  .flow { list-style: none; margin: 0; padding: 0; display: grid; gap: var(--s-3); grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); counter-reset: f; }
  .flow li { counter-increment: f; display: flex; flex-direction: column; gap: 2px; padding: var(--s-3); border: 1px solid var(--border-strong); border-radius: var(--r-sm); background: var(--surface-2); }
  .flow li b::before { content: counter(f) '. '; color: var(--accent); }
  .modes { display: grid; gap: var(--s-2); }
  .mode { display: flex; gap: var(--s-3); align-items: flex-start; padding: var(--s-3); border: 1px solid var(--border-strong); border-radius: var(--r-sm); cursor: pointer; }
  .mode.sel { border-color: var(--accent); background: var(--accent-soft); }
  .block { display: block; }
  .flow li.distinct { border-color: var(--accent); background: var(--accent-soft); }
  .decl { padding-top: var(--s-2); max-width: 32rem; }
  .op { border-top: 1px solid var(--border); padding-top: var(--s-3); margin-top: var(--s-2); }
  .op.off .ophead b { color: var(--fg-subtle); text-decoration: line-through; }
  .ophead { gap: var(--s-3); align-items: center; flex-wrap: wrap; margin-bottom: var(--s-2); }
  .raw { max-width: 22rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .scheme { border: 0; padding: 0; margin: 0; display: grid; gap: var(--s-2); }
  .scheme legend { font-weight: 600; margin-bottom: var(--s-1); }
  .scheme .row { display: flex; gap: var(--s-4); flex-wrap: wrap; }
  .blockers { margin: 0; padding-left: 2rem; }
  .resume { gap: var(--s-2); flex-wrap: wrap; }
  .what { margin: 0; padding-left: 1.2rem; display: grid; gap: var(--s-1); }
  .bulk { gap: var(--s-2); flex-wrap: wrap; }
  .idrow { gap: var(--s-3); flex-wrap: wrap; align-items: flex-start; }
  .adv { border: 1px solid var(--border); border-radius: var(--r-sm); padding: var(--s-2) var(--s-3); }
  .adv summary { cursor: pointer; font-weight: 600; }
  .adv[open] summary { margin-bottom: var(--s-2); }
  .masked, .found, .reasons { list-style: none; margin: 0; padding: 0; display: grid; gap: var(--s-1); }
  .masked li { display: flex; gap: var(--s-2); align-items: center; }
  .found li { display: flex; gap: var(--s-2); align-items: center; flex-wrap: wrap; }
  .reasons { margin-top: var(--s-1); padding-left: var(--s-3); }
  .samp { margin-top: var(--s-3); }
  .navr { gap: var(--s-2); flex-wrap: wrap; }
  .advhint { margin: 0; text-align: right; }
</style>
