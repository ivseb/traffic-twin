# Come si rilascia traffic-twin

Un rilascio ha tre parti con confini netti:

- **Automatica** (workflow `release.yml`, parte da un tag `vX.Y.Z`): compila, firma, produce
  SBOM e provenienza, pubblica l'immagine su `ghcr.io` e prepara una **bozza** di release GitHub.
- **Manuale** (il maintainer, dopo aver controllato la bozza): pubblicare la bozza, e creare i tag
  dei moduli Go annidati (§4).
- **Parte da sola alla pubblicazione della release** (workflow `publish-sdks.yml`): pubblica gli
  SDK su npm, PyPI, NuGet, Maven Central e sul mirror PHP di Packagist, un job indipendente per
  registro (§4).

Pubblicare un pacchetto è un'azione verso l'esterno e **non si può ritirare** (npm, PyPI, NuGet
e Maven Central non permettono di riusare una versione): per questo `publish-sdks.yml` parte solo
quando pubblichi la release (la bozza di `release.yml` non lo fa scattare), a mano gira in
**dry run** se non dici altrimenti, e i suoi job usano l'environment `release`, dove stanno i
segreti e dove si possono richiedere approvazioni.

## 1. Prima del tag

1. `main` è verde (job `ci-ok`, compreso il giro settimanale completo).
2. `make ci-local` passa sulla tua macchina (Docker per i runtime mancanti; `MATRIX=full` per
   l'intera matrice di versioni).
3. Il job `ui` della CI passa: il bundle di produzione non deve contenere codice demo o mock
   (`scripts/ui-forbidden-strings.txt`). Il workflow di rilascio ripete il controllo e si ferma
   se fallisce.
4. Le versioni degli SDK sono quelle volute e coerenti tra loro: manifest **e** costante
   compilata nell'SDK (`sdk/node/package.json` + `src/version.ts`, `sdk/python/pyproject.toml` +
   `_version.py`, `sdk/java/pom.xml` e i `pom.xml` dei moduli + `Version.java`,
   `sdk/dotnet/Directory.Build.props` + `Version.cs`, `sdk/php/src/Version.php`,
   `sdk/go/doc.go`). `composer.json` non ha il campo `version`: per PHP e per i moduli Go la
   versione è il tag. Lo verifica `scripts/sdk-version.sh <sdk> X.Y.Z`, che il workflow di
   pubblicazione esegue per primo in ogni job.
5. Facoltativo ma consigliato, prova generale senza pubblicare né firmare:
   ```sh
   docker run --rm -v "$PWD":/repo -w /repo -v /var/run/docker.sock:/var/run/docker.sock \
     --entrypoint goreleaser goreleaser/goreleaser:v2.19.0 \
     release --snapshot --clean --skip=publish,sign,sbom,before   # serve la UI già compilata (make ui)
   make sdk-package                                                # con i toolchain installati
   ```

## 2. Il tag e il workflow

```sh
git switch main && git pull --ff-only
git tag -s vX.Y.Z -m "traffic-twin vX.Y.Z"      # firmato; per una prova: vX.Y.Z-rc.1
git push origin vX.Y.Z
```

Un tag con suffisso (`-rc.1`, `-beta.1`) diventa una pre-release e **non** sposta i tag
`latest` e `X.Y` dell'immagine.

`release.yml` esegue, in quest'ordine:

| Job | Cosa fa |
|---|---|
| `verify` | fmt, vet, build, test, race, vettori di conformità, build UI di produzione senza stringhe demo |
| `goreleaser` | binari `linux/darwin/windows` × `amd64/arm64` (statici, senza cgo), archivi, `checksums.txt`, SBOM SPDX di ogni archivio (syft), firma keyless del file dei checksum (cosign, `checksums.txt.sigstore.json`), immagine multi-arch `ghcr.io/ivseb/traffic-twin` (con SBOM buildx) firmata per digest con cosign, bozza di release |
| `provenance` | provenienza SLSA livello 3 degli archivi (`slsa-github-generator` v2.1.0), allegata alla bozza come `*.intoto.jsonl` |
| `sdk-dry-run` | `npm pack`, `python -m build`, `mvn package`, `dotnet pack`, `composer validate --strict` e controllo dei moduli Go: i pacchetti restano come artifact del run per 14 giorni, **non** vengono pubblicati |

Non servono segreti: si usano solo il `GITHUB_TOKEN` del run e l'identità OIDC del workflow
(`id-token: write`) per la firma keyless. Il generatore SLSA è l'unica action referenziata
per tag e non per SHA: è il modo in cui i verificatori riconoscono il builder.

### Impostazioni del repository (una tantum)

- Actions: permessi del `GITHUB_TOKEN` "Read repository contents" come predefinito (i job
  chiedono da soli ciò che serve).
- Dopo il primo push dell'immagine, il pacchetto `traffic-twin` su ghcr.io nasce **privato**:
  da "Package settings" collegalo al repository e rendilo pubblico.
- Branch protection su `main`: richiedere il check `ci-ok`.
- Regola di protezione dei tag `v*` (solo i maintainer possono crearli).

## 3. Controllare la bozza e pubblicarla

Sulla pagina delle release (bozza) devono esserci archivi, `checksums.txt`,
`checksums.txt.sigstore.json`, un `.sbom.spdx.json` per archivio e `*.intoto.jsonl`.
Verifica da una macchina pulita:

```sh
# 1. firma dei checksum (keyless: l'identità è il workflow di rilascio di questo repository)
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ivseb/traffic-twin/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt

# 2. provenienza SLSA di un archivio
slsa-verifier verify-artifact tt_X.Y.Z_linux_amd64.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/ivseb/traffic-twin --source-tag vX.Y.Z

# 3. immagine (serve cosign v3 o successivo: le firme sono nel formato nuovo)
cosign verify ghcr.io/ivseb/traffic-twin:X.Y.Z \
  --certificate-identity-regexp '^https://github.com/ivseb/traffic-twin/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker run --rm ghcr.io/ivseb/traffic-twin:X.Y.Z version
```

Se tutto torna: scrivi le note nella bozza (il changelog generato è solo un punto di partenza) e
premi **Publish release**: fa partire `publish-sdks.yml` (§4), quindi gli SDK escono subito dopo.
Se qualcosa non va: elimina la bozza e togli dall'immagine i tag su ghcr.io; il tag va ricreato sul commit corretto solo se nulla è stato pubblicato, altrimenti
passa a `vX.Y.(Z+1)`.

## 4. Pubblicare gli SDK

### Il workflow `publish-sdks.yml`

Parte quando **pubblichi la release** (evento `release: published`; la versione è quella del tag;
una pre-release GitHub fa solo il dry run). Si lancia anche a mano da Actions → *publish-sdks* →
*Run workflow*, con `version` = `X.Y.Z` (senza `v`) e `dry_run` (vero di default). Per pubblicare
davvero a mano scegli il **tag** `vX.Y.Z` in "Use workflow from": su un altro ref il workflow si
rifiuta, perché ciò che esce deve essere il sorgente taggato.

Ogni job, nell'ordine: controlla che manifest e costanti di versione siano esattamente la
versione chiesta (`scripts/sdk-version.sh`), esegue i test dell'SDK (`scripts/sdk-test.sh`),
costruisce il pacchetto (`scripts/sdk-package.sh`, lasciato come artifact `publish-*` per 14 giorni)
e solo allora pubblica. In dry run si fa tutto tranne l'ultimo passo. I job sono indipendenti:
se un registro fallisce gli altri vanno avanti, e il job fallito si rilancia con "Re-run failed
jobs" perché la pubblicazione è idempotente (`--skip-existing`, `--skip-duplicate`, controllo
"versione già presente" per npm e Maven Central, push del mirror senza forzature).

| Job | Pacchetto | Autenticazione |
|---|---|---|
| `npm` | `@traffic-twin/sdk` (npm), con `--provenance --access public` | oggi il segreto `NPM_TOKEN`; se manca, trusted publishing (OIDC, npm >= 11.5.1) |
| `pypi` | `traffic-twin` (PyPI), con attestazioni | trusted publishing (OIDC), nessun token |
| `nuget` | `TrafficTwin.Sdk`, poi `TrafficTwin.Sdk.AspNetCore` (NuGet) | trusted publishing: `NuGet/login` (OIDC) dà una chiave a vita breve |
| `maven` | `io.github.ivseb.traffictwin:sdk-parent`, `sdk`, `sdk-servlet-javax`, `sdk-otel-extension`, `sdk-agent` (Maven Central) | token utente del Central Portal + chiave GPG (segreti sotto); se mancano, il job **salta con una notice** |
| `php` | `traffic-twin/sdk` (Packagist) | chiave di deploy SSH del repository mirror; se manca, il job salta con una notice |

Maven Central: i `pom.xml` hanno i metadati richiesti (nome, descrizione, licenza, sviluppatori,
scm) e il profilo `release` aggiunge jar dei sorgenti e del javadoc, firma GPG (pinentry
loopback, passphrase da `MAVEN_GPG_PASSPHRASE`) e `central-publishing-maven-plugin`
(`autoPublish`, `waitUntil: published`). Le build normali (`mvn package`, la CI) non usano il
profilo. Prova locale senza chiavi: `cd sdk/java && ./mvnw -P release -Dgpg.skip verify`.

PHP: Packagist legge `composer.json` dalla **radice** di un repository, ma qui sta in `sdk/php/`.
Il job fa `git subtree split --prefix=sdk/php` e lo spinge su `main` del repository mirror
`github.com/ivseb/traffic-twin-php` (solo fast-forward) insieme al tag `vX.Y.Z`; Packagist
vede il tag dal suo hook GitHub. La chiave host di `github.com` è fissata nel workflow (non c'è
`ssh-keyscan` a runtime).

Go: nessun job, vedi la sezione successiva.

### Impostazione una tantum già fatta

- npm: organizzazione `traffic-twin`, pacchetto `@traffic-twin/sdk`, segreto `NPM_TOKEN`
  nell'environment `release`.
- PyPI: pending trusted publisher per il progetto `traffic-twin` (owner `ivseb`, repository
  `traffic-twin`, workflow `publish-sdks.yml`, environment `release`). Dopo la prima
  pubblicazione diventa un publisher normale, senza altro da fare.
- NuGet: policy di Trusted Publishing per `ivseb/traffic-twin`, workflow `publish-sdks.yml`,
  environment `release`, pacchetti `TrafficTwin.*`.
- Maven Central: namespace `io.github.ivseb` verificato sul Central Portal.

### Ancora da fare a mano (una tantum)

1. **Maven Central.** Crea una chiave GPG dedicata (`gpg --full-generate-key`) e **pubblica la
   chiave pubblica** su un keyserver (`gpg --keyserver keyserver.ubuntu.com --send-keys <ID>` e
   keys.openpgp.org con la verifica dell'email): Central controlla le firme lì. Poi, nell'environment
   `release` (Settings → Environments), crea i segreti:
   `MAVEN_CENTRAL_USERNAME` e `MAVEN_CENTRAL_PASSWORD` (token utente: Central Portal → Account →
   *Generate User Token*), `GPG_PRIVATE_KEY` (`gpg --armor --export-secret-keys <ID>`) e
   `GPG_PASSPHRASE`. Finché ne manca uno, il job `maven` salta senza fallire. La prima
   pubblicazione su Central è irreversibile: fai prima un dry run e controlla l'artifact `publish-maven`.
2. **Mirror PHP.** Crea il repository **vuoto** `github.com/ivseb/traffic-twin-php` (pubblico, senza
   README né licenza iniziali, altrimenti il primo push non è un fast-forward). Genera una
   chiave dedicata: `ssh-keygen -t ed25519 -N '' -C traffic-twin-php-mirror -f php-mirror-key`;
   la parte pubblica va in Settings → Deploy keys del **mirror** con "Allow write access", la parte
   privata (contenuto del file, formato OpenSSH) nel segreto `PHP_MIRROR_DEPLOY_KEY` dell'environment
   `release`; poi cancella i due file locali. Dopo il primo push registra il mirror su
   packagist.org (*Submit*, URL `https://github.com/ivseb/traffic-twin-php`) e controlla che
   l'aggiornamento automatico (hook GitHub) sia attivo.
3. **npm: passare al trusted publishing.** Dopo la prima pubblicazione col token, su npmjs.com
   (Settings del pacchetto → *Trusted Publisher*) registra GitHub Actions con owner `ivseb`,
   repository `traffic-twin`, workflow `publish-sdks.yml`, environment `release`. Poi **elimina il
   segreto `NPM_TOKEN`** dall'environment, revoca il token su npm e, nelle impostazioni del
   pacchetto, imposta "Require two-factor authentication and disallow tokens". Dal rilascio
   successivo il job usa da solo l'OIDC.
4. Facoltativo: nell'environment `release` metti dei *required reviewers*, così ogni pubblicazione
   (e ogni dry run) chiede una conferma; limita i tag deployabili a `v*`.

Prima del primo vero rilascio fai un giro di prova: Actions → *publish-sdks* → *Run workflow*,
`version` `0.1.0`, `dry_run` attivo.

### Moduli Go (`sdk/go`)

Questo passo è **manuale**: nessun workflow lo fa, perché serve un commit di rilascio senza `replace`.

Il pacchetto `sdk/go` fa parte del modulo radice: basta il tag `vX.Y.Z` già creato. Gli adattatori
`sdk/go/gin`, `sdk/go/chi`, `sdk/go/otelctx` sono moduli separati che oggi usano
`replace github.com/ivseb/traffic-twin => ../../..`: una `replace` non vale per chi li importa,
quindi prima di taggarli va tolta, su un commit di rilascio:

```sh
for m in gin chi otelctx; do
  (cd sdk/go/$m \
    && go mod edit -dropreplace=github.com/ivseb/traffic-twin \
    && go mod edit -require=github.com/ivseb/traffic-twin@vX.Y.Z \
    && go mod tidy && go build ./... && go vet ./...)
done
git commit -am "sdk/go: release vX.Y.Z (drop replace directives)"
git tag sdk/go/gin/vX.Y.Z; git tag sdk/go/chi/vX.Y.Z; git tag sdk/go/otelctx/vX.Y.Z
git push origin sdk/go/gin/vX.Y.Z sdk/go/chi/vX.Y.Z sdk/go/otelctx/vX.Y.Z
```

Il prefisso della cartella fa parte del tag. Il tag `vX.Y.Z` del modulo radice deve esistere
**prima** (il `go mod tidy` lo scarica dal proxy). Dopo il rilascio rimetti le `replace` su `main`
per lo sviluppo. Il proxy Go non dimentica mai una versione: se sbagli, passa alla successiva e
usa `retract` nel `go.mod`.

## 5. Se qualcosa va storto

- **Il workflow fallisce prima di `goreleaser`**: correggi su `main`, cancella il tag
  (`git push --delete origin vX.Y.Z; git tag -d vX.Y.Z`) e ricrealo sul commit nuovo. Nulla è
  stato pubblicato.
- **Fallisce dopo il push dell'immagine**: l'immagine c'è già su ghcr.io. Se la release non verrà
  pubblicata, elimina la versione del pacchetto da GitHub (Packages) prima di riprovare.
- **`publish-sdks.yml`: un job fallisce, gli altri no**: correggi la causa (segreto mancante,
  regola di trusted publishing, rete) e rilancia solo i job falliti; i registri già serviti
  restano com'erano. Se un pacchetto è uscito ma è sbagliato, quella versione non si riusa:
  correggi e passa a `vX.Y.(Z+1)` (poi `npm deprecate`, yank su PyPI, unlist su NuGet).
- **Vulnerabilità trovata dopo la pubblicazione**: rilascia una versione corretta, poi
  `npm deprecate`, "yank" su PyPI, unlist su NuGet o `retract` in Go per le versioni colpite;
  vedi anche `SECURITY.md`.

## 6. Provare tutto in locale

```sh
make ci-local                      # gli stessi controlli della CI, Docker per i runtime mancanti
make ci-local ONLY="go ui"         # solo alcuni passi (elenco in scripts/ci-local.sh)
make ci-local MATRIX=full          # tutta la matrice: Node 20/22/24, Python 3.9/3.11/3.13, JDK 17/21, .NET 8/10, PHP 8.1/8.3/8.4
make ci-local ONLY=sdk-package     # costruisce i pacchetti di tutti gli SDK come fa la pubblicazione (senza pubblicare)
make actionlint goreleaser-check   # validazione dei workflow e di .goreleaser.yaml
```

## 7. Rotazione della chiave di firma delle policy (operazioni)

La chiave di firma delle policy di keyguard si ruota senza rilasciare nulla, ma con un ordine preciso: chiave nuova in
prima riga **tenendo il seed della vecchia**, attesa delle conferme delle sorgenti, revoca da **Impostazioni → Chiavi di
firma**, chiusura in keyguard. Il runbook passo per passo, con la revoca d'emergenza di una chiave compromessa, è in
[deploy/README.md](deploy/README.md#rotazione-della-chiave-di-firma-delle-policy); le regole in
[docs/spec/policy.md](docs/spec/policy.md) §3.1.

Per un rilascio questo significa:

- un SDK che cambia la gestione delle chiavi DEVE applicare `revoke_signing_keys` prima di `add_signing_keys`, ignorare
  in silenzio le chiavi già fissate e inviare `signing_kids` nell'heartbeat: lo verificano i test di rotazione di ogni
  SDK e `test/redteam/r3` (`go test ./test/redteam/r3/ -run Key`, `node --test test/redteam/r3/node/rotation.test.mjs`);
- nelle note di rilascio va scritto se la versione cambia il formato del file delle chiavi o il default di
  `fleet.key_rotation` (`min_confirmed: 1`, `window: 24h`): con sorgenti su SDK vecchi, che non inviano `signing_kids`,
  la revoca di una chiave resta bloccata finché non si aggiornano.
