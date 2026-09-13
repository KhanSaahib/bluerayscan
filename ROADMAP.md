# Roadmap

The backlog for bluerayscan, roughly in priority order. Work moves top-down.
Tick an item when it lands on `main` with tests and a green CI run.

Anything here can be reordered, rewritten, or dropped if it turns out to be a
bad idea. A crossed-out item with a note explaining why it was wrong is a
better outcome than a feature nobody wanted.

## Detection quality

- [x] Allowlist documented public example credentials so the scanner stops
      flagging documentation
- [x] Respect `.gitignore` when walking a repository, nested files included,
      with `--no-gitignore` to audit what was hidden
- [x] File-level, block-level and rule-scoped suppression, each counted in the
      summary so silence is never free
- [x] Baseline file with fingerprints that omit line numbers, plus
      `--prune-baseline` for entries that match nothing
- [x] ~~Track the entropy floor separately per rule~~ — per *rule* was the wrong
      axis. The threshold depends on the value's own alphabet and length, which
      is what `heuristics.entropy_floor` measures
- [x] Secrets in value positions (`.env`, `.npmrc`, `.pypirc`, Compose), where
      there is no quoted assignment to match
- [x] Confidence as an axis of its own, weighed by where the file sits, with
      `--min-confidence` to gate on it
- [x] GCP service account JSON as a whole document (SEC021), and credentials
      hidden inside base64 (SEC022)
- [x] Multi-line detection, in the one shape that was actually costing
      findings: a value written on the lines beneath its name, which is how
      YAML carries anything long. A PEM body is still read from its header
      line, which is the line that identifies it
- [x] ~~Report the *shape* of a near miss: a value that failed the entropy
      floor by a hair next to a credential-shaped name~~ -- measured and
      refused. At a margin of a tenth of a bit it is 172 findings across the
      twenty-one pinned repositories and one of them is worth reading; the
      rest are one variable assigned to another, a class name, a Vault
      reference. The floor's margin is what holds those back. Numbers in
      `docs/RULES.md`
- [x] The question that idea was asking -- *did you miss my secret?* -- gets
      an answer that costs nothing instead: `bluerayscan explain VALUE
      --name NAME` prints the measurements and says what would happen to it
- [x] Report the first-seen commit: `bluerayscan history` reads a `git log -p`
      stream and names the commit that introduced each credential, earliest
      first. This tool still does not run git; the caller does
- [ ] ~~Say whether a found credential is *live*, rather than merely public
      (`--verify`)~~ — off by default and probably always. Nothing local can
      answer it, and the only thing that can is an outbound request carrying
      the credential this tool is unsure about, to somebody else's service.
      "Public since March" is the part that is knowable here, and it is the
      part that decides the rotation

## Workflow and CI analysis

- [x] Per-job `permissions:` analysis, `write-all`, secrets passed to a
      third-party action, `workflow_run` checking out the triggering head,
      self-hosted runners, and a token that outlives its step
- [x] GitLab, Azure Pipelines, CircleCI and Jenkins, each with its own
      injection vocabulary and its own quoting rules
- [x] ~~Reusable workflow calls (`uses:` at job level) pinned to a mutable
      ref~~ -- already covered: WF001 reads any `uses:`, with or without the
      list dash. WF011 is the part that was actually missing, and it is about
      the secrets, not the ref
- [x] Warn on `contents: write` without an obvious need (WF013). The notion of
      "obvious need" turned out to be: anything that could be writing counts,
      including a local composite action and a reusable workflow, because the
      reader cannot see inside either. One finding across twenty-one
      repositories, and it is real
- [x] Composite actions in the repository itself (`action.yml`), which are
      workflows in all but trigger. WF012 is the rule that only makes sense
      there: an action cannot tell a safe input from a dangerous one

## Beyond GitHub Actions

- [x] Dockerfiles, Compose, Terraform, CloudFormation, Kubernetes, Ansible,
      dependency manifests, shell scripts and Makefiles
- [x] Helm `values.yaml` -- read where a `Chart.yaml` sits beside it, for the
      settings that carry their meaning wherever they are written. Reading it
      *against the templates* is still open, and would answer the question
      this cannot: whether the chart passes the value through at all
- [x] Kustomize overlays: the manifests a kustomization patches in are read,
      with the line numbers shifted so a finding points at the patched line
- [x] ~~systemd units and cron files as a family~~ -- they did not need one.
      A unit is an INI file and a crontab is assignments, so both became
      value-position formats for the rules that already read those
- [x] More application-code idioms, measured against nineteen repositories:
      AP004 (unsafe deserialisation), AP005 (a password through a fast digest)
      and AP006 (a shell command built by interpolation). The family is seven
      rules and reads five languages
- [x] A seventh: AP007, a JWT accepted with the "none" algorithm. It has
      exactly one meaning in each of the three languages it is read in, which
      is the bar -- an idiom with one meaning, read only where it has that
      meaning, which is what keeps this family seven rules rather than thirty.
      Fires no times across the twenty-one pinned repositories, which is the
      expected result
- [ ] An eighth, on the same terms. Candidates that have not cleared the bar,
      and why:
      - **PyJWT's unverified decode** with no second decode after it --
        measured at twenty-one findings across the pinned repositories, every
        sampled one of them the honest two-step, so telling them apart needs
        to see the decode that follows
      - **A weak TLS version** named as the floor (`ssl.PROTOCOL_TLSv1`,
        `MinVersion: tls.VersionTLS10`, `minVersion: 'TLSv1.1'`) -- measured
        at **one** finding across the twenty-one, and that one a test asserting
        a target's TLS policy is *not* propagated to a proxy handshake. The
        idiom does have a single meaning; there is simply almost nothing to
        find, and the first draft of its pattern already read `TLSv1_2_method`
        as weak. Worth revisiting only alongside a corpus where it appears
      - **Hardcoded JWT signing secrets** -- a credential, so the secret rules
        are the right family for it, not this one
      - **DEBUG in frameworks other than Django and Flask** -- the word means
        something different in each, which is the bar failing
      - **Permissive CORS** -- `*` is only a problem with credentials, and the
        line does not say whether there are any
      - **SQL built by string formatting** -- the classic, and the most
        expensive thing measured here: **344** findings across the twenty-one,
        none of them a reviewer would want. 311 in JavaScript and TypeScript,
        of which the reader cannot even tell a database `.query()` from
        supertest's HTTP one or a Prometheus client's; 30 in Go, 28 of them one
        Postgres state backend; 3 in Python. Every true match interpolates a
        *table or schema name*, and that is the structural reason the rule
        cannot work: the one thing SQL will not let you bind is an identifier,
        so the legitimate use of string formatting in a query has exactly the
        shape the rule looks for
      - **Request data inside a query** -- the narrower shape that works for
        AP006, measured across Python, PHP, JavaScript and TypeScript: **zero**
      - **Unsafe deserialisation beyond AP004** -- `pickle.loads` in Python,
        five findings, every one of them a Django session or cache backend
        reading bytes it wrote itself and every one already carrying a `#
        nosec`; Ruby's `YAML.load` and `Marshal.load`, seven, two of them the
        `Marshal.load(Marshal.dump(x))` deep-copy idiom and two already
        carrying a `rubocop:disable`. Twelve findings, no reader wanted any of
        them, and the authors had already said so in the file
      - **A world-writable `chmod 0777`** -- four, all `os.MkdirAll` on a
        scratch directory in a Go test, where the umask has the last word anyway
      - **React's `dangerouslySetInnerHTML`** -- two, both rendering the
        highlight markup a search API returned
      - **Django's `ALLOWED_HOSTS = ["*"]`** -- one, and a real one, which is
        why it still fails: Django's own documentation calls `*` acceptable
        where a reverse proxy validates the Host header, and the settings line
        does not say whether there is one. Two readings, so not one meaning
      - **CSRF switched off** (`@csrf_exempt`, `CSRF_COOKIE_SECURE = False`,
        `WTF_CSRF_ENABLED = False`) and **`os.system` with an interpolated
        argument** -- **zero** each
      - **ECB mode, DES and RC4, `tempfile.mktemp`, XXE via
        `resolve_entities=True`** -- **zero** each. Like the weak-TLS-version
        candidate, these clear the one-meaning bar and have nothing to find in
        this corpus; twenty-one well-maintained repositories have had these
        linted out of them for years

## Output and integration

- [x] SARIF with stable partial fingerprints, CWE tags and help URLs
- [x] JUnit XML, which GitLab, Azure and Jenkins render without a plugin
- [x] Pre-commit hook, GitHub Action wrapper, `rules` command, `init` command
- [x] `--paths-from FILE` for per-PR runs, `--format markdown` for a PR comment,
      `--format github` for annotations
- [x] `--quiet`, `--sort`, `--disable`, per-path configuration
- [x] `--fail-on none`, so a reporting job need not borrow its CI's word for
      "do not stop here"
- [x] Every skip counted and named: unreadable paths, files over the size
      limit, suppression markers -- in the sentence, in the JSON, and in the
      SARIF invocation
- [x] ~~`--explain RULE`~~ -- a flag was the wrong shape. `rules WF011` already
      names one rule; it now prints the card instead of the row, which is what
      the flag would have done and one fewer thing to know
- [x] Group findings by file in text output, under `--sort path`
- [x] Publish to PyPI so `pipx run bluerayscan` works, using trusted
      publishing with no long-lived upload token

## Engineering health

- [x] A corpus that trips every rule, asserted four ways against the catalogue,
      the scanners, the docs and the severity ceiling
- [x] Coverage measurement in CI with a floor, using the standard library
- [x] Property-based and seeded-fuzz tests over all three readers, with time
      bounds and scaling guards for the shapes that were quadratic
- [x] Type annotations checked with mypy in CI
- [x] Issue templates, CONTRIBUTING.md, SECURITY.md
- [x] Benchmark against large repositories: the Python standard library went
      5.1s → 1.3s, Prometheus a five-minute timeout → 3.7s
- [x] A fixed corpus of real repositories pinned by commit, so a heuristic
      change can be measured rather than argued about (`tools/corpus.json`,
      `measure.py --fetch/--save/--compare`)
- [x] CodeQL default setup, over Python and Actions both, and branch
      protection on `main`: ten required checks, linear history, no force
      pushes
