// Localization of the install snippets that tt-core writes (internal/fleet/snippets.go): titles by snippet id,
// comment lines by their exact English text. The Go test TestSnippetCommentsHaveATranslation checks that every
// comment the server writes is listed here.
import { tk } from '../../i18n/index.svelte';

/** English comment (as written by the server) -> i18n key. */
export const SNIPPET_COMMENTS: Record<string, string> = {
  '# HMAC key: the installation-wide file from your platform team (one line <kid>:<base64url>,': 'snip.c.key1',
  '# same kid as the policy hmac.kid, e.g. k1, and the same key keyguard holds). Never commit it.': 'snip.c.key2',
  '# Until the SDK is on your registry, install the file of the kit: npm install ./traffic-twin-sdk-<version>.tgz': 'snip.c.tgz',
  '# Pass TT_ENROLL_TOKEN at run time (secret), never bake it into the image.': 'snip.c.secret',
  '# Mount the HMAC key file at run time (e.g. -v /etc/traffic-twin:/etc/traffic-twin:ro).': 'snip.c.mount',
  "# then point the application's external base URLs (or HTTPS_PROXY) at tt-egress": 'snip.c.egress',
  '# download traffic-twin-agent.jar from your internal artifact registry': 'snip.c.jar',
  '# publish the hook once (it brings TrafficTwin.Sdk and TrafficTwin.Sdk.AspNetCore) from sdk/dotnet, or copy it': 'snip.c.hook1',
  '# from your internal artifact registry:': 'snip.c.hook2',
  '# Program.cs: builder.Services.AddTrafficTwin(); ... app.UseTrafficTwin();': 'snip.c.nuget',
  '# node | python | java | dotnet | go | php: one token serves all of them': 'snip.c.langs',
  '# Install the wheel of the kit (once the SDK is on your registry: pip install traffic-twin)': 'snip.c.wheel',
  '# Use your own server command: gunicorn app:app | flask --app app run | python manage.py runserver': 'snip.c.pyrun',
  '# Inbound capture is automatic for Flask, FastAPI/Starlette, Django and apps loaded by uvicorn or gunicorn;': 'snip.c.pyin',
  '# requests and httpx calls are captured too (TT_OUTBOUND=off turns the outgoing side off).': 'snip.c.pyout',
};

/** Snippet ids with a translated title. */
export const SNIPPET_IDS = [
  'node', 'node-docker', 'python', 'python-code', 'java', 'dotnet-hook', 'dotnet-nuget', 'go', 'go-code', 'php', 'egress-helm', 'egress-docker', 'obi', 'obi-secret', 'import', 'k8s-secret', 'k8s-annotations',
] as const;

/** Title in the console language (the server's English title when the id is unknown). */
export function snippetTitle(id: string | undefined, title: string): string {
  return id ? tk(`snip.t.${id}`, undefined, title) : title;
}

/** Replaces the known English comments (whole lines or trailing comments) with their translation. */
export function localizeSnippet(text: string): string {
  return text
    .split('\n')
    .map((line) => {
      const i = line.indexOf('# ');
      if (i < 0) return line;
      const comment = line.slice(i);
      const key = SNIPPET_COMMENTS[comment];
      return key ? line.slice(0, i) + tk(key, undefined, comment) : line;
    })
    .join('\n');
}
