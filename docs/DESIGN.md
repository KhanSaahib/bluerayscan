# Design

How the pieces fit, and why they are shaped the way they are. This is for
someone about to change the code; [RULES.md](RULES.md) is for someone about to
read a finding.

## The pipeline

```
discovery.walk ──► Entry(path, text|None)
                        │
                        ├─► scanners.filenames      (names, including binaries)
                        ├─► scanners.secrets        (every text file)
                        └─► the format scanners     (each filters by content)
                                    │
                                    ▼
                              list[Finding]
                                    │
                        engine.collapse ──► sort ──► CLI filters ──► report
```

Four things happen in that order and the order matters:

**The walk yields every path it reaches**, with text where it could read it and
`None` where it could not. Two of the three reasons it could not are counted
and reported -- a path it had no permission for, a file over the size limit --
because both are gaps somebody should be able to see. A binary is the silent
one: its bytes are not text in any sense a rule could read. Before that, a binary was dropped before any rule
saw it, which made a committed `id_rsa` or `.p12` invisible. A scanner that
only ever sees text cannot report a file that has none.

**Each scanner decides for itself whether a file is its business**, and mostly
by content rather than by path. A Kubernetes manifest is a document with
`apiVersion` and `kind`; a Compose file is one with a `services` map and no
`apiVersion`; a GitLab pipeline is one named `.gitlab-ci.yml` *or* one whose
top-level keys carry scripts. Directory conventions are guesses, and a workflow
file living in `k8s/` is not a workload.

**`engine.collapse` drops the second report of one problem.** Scanners overlap
deliberately -- a credential inside a Kubernetes `Secret` is both a manifest
problem and a secret -- and each rule says something the other cannot. What
collapses is an explicit `subject`: the redacted credential. Nothing else
participates, because two rules can legitimately report the same line for
different reasons, and an earlier version keyed on evidence text quietly ate
findings that way.

The same subject in the same file is then folded across lines and counted.
One credential is one thing to rotate however many times it was pasted, and
Discourse has a presigned URL in a fixture whose access key id appears on 758
lines. Findings *without* a subject are never folded, because there each line
is its own edit: five unpinned actions in one workflow are five pins to write.

**Filtering happens after scanning, never during.** Severity, confidence,
disabled rules and the baseline are all decisions about which findings to
*show*. Keeping them out of the scanners means a rule cannot accidentally
become unreachable, and means every filter can report what it hid.

## The three readers

`hcl`, `yamlish` and `jsonish` exist because most rules ask questions about a
*block*, and a line cannot answer them. `privileged: true` under
`securityContext` is critical and the same line under `annotations` is nothing;
`cidr_blocks` in an `ingress` block is a finding and in `egress` it is normal.

None of them is a parser, and each says so in its module docstring. The rule
they follow is that **unknown structure degrades to a scalar**, never to a wrong
shape: a flow collection, an anchor, a tag comes through as text, so a rule
looking for nesting finds none and stays quiet. Silence is the safe direction
for a parser this small, and it is the only direction that lets the zero
dependency rule survive contact with real files.

Line numbers are carried on every node. A finding that points at the wrong line
of a Helm chart is worse than no finding, which is why template flattening
replaces expressions in place rather than deleting them.

## Severity and confidence

They answer different questions and collapsing them loses both.

*Severity* is what the finding costs if it is real. *Confidence* is how sure
the rule is that it is. A documented token shape is high confidence; entropy
next to a variable named `api_key` is a guess and says so.

Two consequences worth knowing before touching a rule:

- The catalogue's severity is the **worst case**, asserted by a test. A rule
  may grade itself down by context -- TF001 is critical at port 22 and high at
  443 -- but never up past what the catalogue promises.
- Confidence is weighed by **where a file sits**. A rule already at medium
  drops to low in fixture trees and documentation, because a credential in
  `testdata/` or a README is usually invented. The config families are weighed
  the same way for a different reason: a pipeline under `docs/` is a snippet in
  a tutorial, and nothing schedules it. Nothing is silenced either way: a real
  key does get committed to a fixture directory, and repositories do ship the
  manifest they actually apply inside their documentation tree.

If you find yourself lowering a severity because a rule is unreliable, lower
the confidence instead. That is what it is for.

### The corpus, and what a round adds to it

The precision programme reads every finding in a repository the corpus has
never seen and fixes what is wrong. A repository that produced a fix then has a
claim on being pinned, because an unpinned one protects nothing: round eight
can silently undo what round five fixed, and the comparison that would have
caught it never runs. Five were pinned after rounds four to seven -- plausible,
bitwarden-server, signal-ios, signal-android and bazel -- each for a language
or a file format none of the other twenty-one carried.

Three more were read in full and deliberately left unpinned, because a pin
costs every future measurement twice over and costs a contributor a clone.
terraform-provider-aws is 87 seconds of scan for one class that was already
correct; azureml-examples is 931 MB for a behaviour a unit test pins with a
synthetic payload; azure-pipelines-tasks is 251 MB for a single class. The
reasoning is in `tools/corpus.json` beside the pins, where somebody proposing
a twenty-seventh will read it.

One consequence worth knowing when reading older numbers: every measurement
recorded before that change -- in `ROADMAP.md`, in `CHANGELOG.md`, and in the
prose here and in `docs/RULES.md` -- was taken across **twenty-one**
repositories, and says so. They are records of what was measured, not claims
about the corpus's present size, and they have deliberately not been restated.

### Findings left alone on purpose

Some of what the programme reads is right, and some is wrong in a way no narrow
fix reaches. Both get written down, so the next person reading the same output
does not re-derive the argument.

- **`check_hostname = False` inside `if not validate_certs:`** (ansible). A
  correct finding about a line that is guarded. Telling them apart needs
  control flow, which no family here has.
- **A MIME database entry describing a PEM file's magic bytes** (nextcloud,
  `freedesktop.org.xml`). There is no narrow fix, and failing towards reporting
  is the right direction for a private key.
- **Sixty `verify=False` in test trees** (airflow). Every one is a test
  asserting that the parameter is forwarded to the AWS hook, and every one is
  already at medium confidence because of where it sits, so
  `--min-confidence high` does not show them. The rule is right, the
  downgrade is right, and the volume is a property of the repository.
- **A connection string in a Python docstring** (airflow, `kylin_cube.py`:
  `kylin://ADMIN:KYLIN@sandbox`, right after "for example:"). <!-- bluerayscan: ignore[SEC020] -->
  Documentation inside a source file, which the path-based downgrade cannot
  see. The marker on the line above is this entry proving its own point. Knowing it is a docstring needs multi-line state in the secret scanner,
  and a credential in a URL is worth failing towards reporting.
- **Sixteen `api_key="echargetoday"`** (home-assistant, `growatt_server`). The
  vendor's own API field names, assigned to a dataclass field called
  `api_key`. Separating them from the real embedded key three files away --
  `API_KEY = "k6Qa...lCC3"`, which the same rule found and which is a true
  positive -- means telling a generated string from an English compound. That
  is the near-miss measurement all over again, and it came out at 172 findings
  and one worth reading.
- **Twelve JSON Web Tokens in fixture trees** (home-assistant). Expired
  specimens, and the rule reports them at high confidence because a JWT is a
  JWT. Reading the `exp` claim would silence them, and would also silence a
  live token that happens to have expired since it leaked.
- **Seventy keystores and seventeen private keys** (keycloak). An identity
  provider's test tree needs a working PKI, and every one of those files is
  what it says it is. FN001 and SEC004 are both right; `docs/RULES.md` names
  the two ways to live with it, and neither is a change to a rule.
- **Nine `check_hostname = False` and `verify=False` in shipped source**
  (home-assistant). Correct, deliberate, and the project knows: they are how
  a local device with a self-signed certificate is reached. A scanner saying
  so is the scanner working.
- **A hundred-odd host-path mounts, `curl | sh` installs and privileged
  containers** across airflow, home-assistant, keycloak and vector. Every one
  correct. A log collector does mount `/var/log`, and `rustup` is installed
  the way rustup says to install it. These are the findings the confidence
  axis cannot help with, because the rule is not guessing -- the reader has to
  decide, and the report exists to put it in front of them.
- **A hundred RSA private keys in one Rust source file** (bitwarden,
  `util/RustSdk/rust/src/rsa_keys.rs`). The file opens with six lines of
  comment saying they are test-only, and they are real PKCS#8 keys all the
  same. SEC004 reports the file once, at critical, and that is the right
  answer: a comment above a key is not a property of the key. What the comment
  *is* good for is the reviewer's decision, which is why the evidence line
  carries the file and not a verdict.
- **A Duende IdentityServer licence key** (bitwarden,
  `src/Core/Settings/GlobalSettings.cs`). A signed JWT, committed, naming
  Bitwarden Inc. and an expiry in December 2026. SEC009 is right that it is a JWT and
  right that it is in shipped source. It is also a licence rather than an
  authentication credential, and no rule can read that distinction out of the
  bytes -- the claims that say so are vendor-specific. Reported at medium,
  which is where a finding a human has to judge belongs.
- **Four database ports published in a development compose file** (bitwarden,
  `dev/docker-compose.yml`: 1433, 5432, 3306, 6379). DC005 is correct and the
  file's directory is the whole argument against caring. `dev/` is not a
  fixture tree and this tool does not treat it as one, because the day a
  `dev/` compose file is copied into a deployment is the day the finding
  matters. A per-path rule in the config is the honest way to say "not here".
- **Three `execSync` calls built from template literals** (plausible,
  `tracker/compiler/analyze-sizes.js`). AP006 is right about the shape. The
  interpolated value is a filename the script just produced, which is the
  reading a human does in four seconds and a rule cannot do at all.
- **A Google Maps key in a Gradle build file** (signal-android,
  `app/build.gradle.kts`: `manifestPlaceholders["mapsKey"]`). The same key
  class as the two weakened beside it, in a file that is not Google's
  generated client configuration and does not say what the key is for. A key
  pasted into a build script could be anything, and an unrestricted Maps key
  is a real billing incident, so this one stays at high confidence.
- **A keystore in a test resources tree** (signal-android, `ias.jks`). FN001
  saying, correctly, that no text rule can read inside it. Same answer as
  keycloak's seventy: a baseline, or a per-path rule.
- **Eight hundred unpinned actions across three hundred and fifty-five
  generated workflows** (azureml-examples). Every one correct, and the volume
  is the point rather than a defect: a repository that generates a workflow
  per example generates the same finding per example. `bluerayscan init`
  records them once.

- **Three encrypted RSA private keys in test fixtures** (azure-pipelines-tasks,
  `Tasks/SshV0/Tests/` and `Tests-Legacy/L0/CopyFilesOverSSH/`). SEC004 at
  critical and high confidence, which is deliberate: a fixture tree lowers the
  rules that were already guessing, and a documented shape is not one of them.
  A task that copies files over SSH needs a working key to test against.
- **A real Giphy API key in shipped source** (signal-ios,
  `SignalServiceKit/Network/API/Giphy/GiphyAPI.swift`). A true positive, three
  lines from two constants whose value is their own name — which is the whole
  argument for the identifier filters being narrow rather than generous.

- **Four hundred and seventy Terraform findings in a provider's test data**
  (terraform-provider-aws, `internal/service/*/testdata/`). Open security
  groups, public S3 ACLs, `Action: "*"` with `Resource: "*"` -- every one of
  them correct, and every one of them the fixture a provider needs in order to
  test that it can create the thing. The confidence axis already handles it:
  they arrive at medium and low, not high. This is what a fixture tree lowering
  is *for*, and it is the largest example the programme has found.
- **Two inputs interpolated into one shell command** (terraform-provider-aws,
  `.github/actions/community_check/action.yml:44`). Reported twice on the same
  line, which looked wrong and is not: the line really does interpolate
  `inputs.core_contributors` and `inputs.user_login`, and both are the
  composite action's own untrusted inputs.

- **A JSON example inside a Javadoc comment** (spring-boot,
  `CloudFoundryVcapEnvironmentPostProcessor.java`: a sample `VCAP_SERVICES`
  blob with `"password":"pxLsGVpsC9A5S"` in it). <!-- bluerayscan: ignore[SEC100] -->
  The one medium-confidence false positive the JSON change introduced across
  the whole corpus, and the same class as the connection string in a Python
  docstring above: documentation inside a source file, which the path-based
  downgrade cannot see. Quoting it here tripped the rule on this file, which
  is the second entry in this list to prove its own point; the marker on the
  line above is the answer both times.
- **Two hundred and forty passwords in a password manager's seed data**
  (bitwarden-server, `util/Seeder/Seeds/fixtures/ciphers/`). Correct, and
  uniquely pathological: the fixture is a vault, so every item in it has a
  generated password. They arrive at low confidence because the tree is a
  fixture tree, which is the whole reason that axis exists.

## Five CI systems, one bug

GitHub expands `${{ github.event.issue.title }}`, GitLab expands
`$CI_COMMIT_TITLE`, Azure expands `$(Build.SourceVersionMessage)`, CircleCI
expands `$CIRCLE_BRANCH`, and Groovy expands `${env.BRANCH_NAME}` -- each into
the command line, before the shell parses it, each from a value an outside
contributor writes. The syntax differs; the bug does not.

Jenkins is the one that does not share the machinery, because its pipelines are
Groovy rather than YAML, and it earns its own rule anyway: there the *quoting*
decides whether the interpolation happens at all.

`scanners/ci.py` holds the parts that do not depend on syntax: finding the
shell lines in a step, and the list of fields that cannot carry an injection.
Each scanner keeps its own pattern and vocabulary, because those are exactly
what differ. The reason to share the rest is not brevity -- it is that a fix
found in one system belongs in all of them, and the harmless-fields list was
written for GitHub and then written again, identically, for Azure.

## Configuration, and the one family that is not

Every family but one reads configuration, and that is a deliberate line.
Configuration says what a system *is*, so a reader that understands its shape
can answer a question about it exactly: `privileged: true` under
`securityContext` means one thing and there is nothing else it could mean.

Code says what a system *does*, and answering a question about that needs
something this tool does not have -- a parser, a call graph, and a notion of
which values reach which calls. So the application-code family
(:mod:`scanners.appcode`) asks a smaller question on purpose: does this file
contain one of a handful of idioms whose meaning is fixed, in a language where
that spelling means what it looks like? `verify=False` is a Python spelling; the
same characters in a Go file are a guess, so the rule does not apply there.

That smallness is the point. A clean report from that family means "none of
these idioms appears", and the documentation says so in those words rather
than implying a coverage that would need a compiler.

## Two gates in front of the patterns

Almost no line in a repository contains a credential, and the scanner's cost is
dominated by proving that about each one. So the secret rules run behind two
cheap questions.

The first is one small pattern: does this line have a fourteen-character run of
credential characters, a PEM header, or a URL carrying a password? Four fifths
of lines do not. The second is per rule: does the line contain any of the
literals that rule's shape must include -- `AKIA`, `ghp_`, `xoxb-`? Nine of the
remaining lines in ten do not.

The application-code family has the same arrangement for the same reason: a
TypeScript monorepo is mostly files that mention "debug" and nothing else, and
running the other thirteen patterns over each of them was the single largest
cost in a scan of one -- 82 seconds down to 57 on n8n once each rule checked
for its own word first.

The entropy rules have a gate of their own, and it is the same idea a third
time: both ultimately need a name carrying one of a dozen words, so a flat
alternation of those words runs first. It is cheap because there is nothing in
it to backtrack over, and the patterns it stands in front of are the opposite
-- each has a greedy character class before its alternation, so the engine
retries at every position on a line that was never going to match. Nine lines
in ten of a source tree mention none of the words.

Both are correctness risks as much as speed wins, because a line a gate rejects
is never looked at again, and a hint absent from what a pattern matches
disables that rule silently. The corpus test is what makes them safe: every
rule must fire on a line carrying its own shape, so a bad gate or a bad hint
fails the build rather than quietly removing a rule.

### What the gates did not turn out to be worth

Four things were measured and are not here, recorded so nobody spends the
afternoon again. A profile of a scan of n8n -- 28,546 files, five million
calls to `scan_line` -- puts a fifth of the time in `re.search` itself and a
seventh in the provider hint loop, and the rest spread thin.

- **Folding the provider hints into one pattern with a lookahead**: slower than
  seventy-two substring tests.
- **Folding them into one plain alternation and reading which hints matched**:
  eleven per cent faster and *wrong*, because `finditer` does not find
  overlapping matches and one hint inside another goes missing. Ninety lines in
  twenty thousand selected a different set of rules.
- **Bucketing the hints by first character**, so that only the hints whose
  first character appears in the line are tested: exactly the same speed. The
  `set(line)` it needs costs what it saves.
- **A whole-file gate in front of the per-line loop**, skipping a file when
  neither the candidate pattern nor the credential word appears anywhere in it.
  Correct, and it skips one file in seven -- and saves no measurable time,
  because the files it skips are the short ones that cost nothing to read. The
  time is in the large files, and a large file always contains a
  fourteen-character run of credential characters.

What is left is architectural -- a process pool, or a different tokenising
strategy -- and neither is worth the complexity at five hundred files a second.
Caching `yamlish.Node.walk()` was inside the noise too.

## The catalogue

`rules.py` lists every rule, and the scanners hold the detection logic and the
remediation text. That duplication is deliberate and defended by a test with
three assertions: every rule a scanner emits is in the catalogue, every
catalogue entry is reachable from a scanner, and every rule appears in
`docs/RULES.md`. A corpus in `tests/corpus.py` trips all of them.

The effect is that a rule cannot ship undocumented, a deleted rule cannot leave
its entry behind, and the README's tables cannot describe the release before
last. Adding a rule means touching four places, and the build says which one
you forgot.

## Suppression and configuration

Three scopes of marker -- line, block, file -- each able to name the rules it
means (`# bluerayscan: ignore[K8S008]`). A configuration file supplies
defaults, including rules disabled globally or under a glob.

Two invariants hold across all of it:

- **The command line always wins.** A config file can never stop somebody
  auditing their own repository more strictly than the project usually does.
- **A gap in the scan is reported, not swallowed.** A directory the process
  cannot open is skipped -- a scanner that dies on one permission error is
  useless in CI -- but the run says how many paths that happened to. "No
  findings" from a tree that was never read is the most dangerous answer this
  tool can give.
- **Silence is always counted, and can always be read past.** A disabled rule,
  a baselined finding, a suppressed line: each is reported as a number in the
  output, and each has a flag that ignores it -- `--disable` is answered by the
  count, the baseline by `--write-baseline`, the markers by `--no-suppression`,
  `.gitignore` by `--no-gitignore`, and the example allowlist by
  `--no-example-allowlist`. Silence nobody can see is the failure this whole
  tool exists to avoid, and a scanner that can be switched off invisibly is
  worse than no scanner.

The unterminated suppression block is the same principle as a rule: SEC900
reports a marker that silences the rest of a file, because otherwise the file
goes quiet and looks clean.

## No dependencies

Not one, at runtime. A tool pointed at your supply chain should not enlarge it,
and the constraint has been good for the design: it is why the scanners read
structure the way a reviewer skims it rather than building trees nobody asked
for, and why the coverage tool in `tools/` is fifty lines of `dis` and
`sys.settrace`.

What it costs is stated where a user can see it: exotic formatting slips past,
JSON CloudFormation templates are not read, and a value arriving through a
variable is invisible. A scanner that implies more coverage than it has is
worse than one that admits its edges.

## Adding a rule

1. Detection in the scanner for that format. Provider patterns are data; the
   structural rules are functions taking a parsed block.
2. An entry in `rules.py`.
3. A fixture in `tests/corpus.py` that trips it.
4. A row in `docs/RULES.md`.
5. Tests for what it should *not* match -- which matters more than the positive
   case, because that is why anyone still has it switched on next quarter.
6. `python3 tools/measure.py` over real repositories before trusting a
   heuristic. Every false positive this project has fixed came from reading
   real output, and not one was imagined in advance.
