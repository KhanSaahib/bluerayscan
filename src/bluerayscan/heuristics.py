"""Deciding whether a string looks like a generated credential.

Every rule that is not a documented token shape ends up here: the entropy
rule, the value-position rules for ``.env`` files, the Dockerfile ``ENV``
check. Keeping the judgement in one module means a placeholder that one rule
learns to ignore is ignored by all of them.

The interesting part is the entropy floor. A single global threshold cannot
work, because the maximum entropy a string can reach depends on both its
alphabet and its length: a 12-character hex token tops out at 3.58 bits per
character and a 200-character base64 blob at 6, so one number is simultaneously
too strict for the first and too lax for the second. What generalises is the
*ratio*: a generated credential lands near the ceiling of what its alphabet and
length allow, and a hand-written value lands well below it.
"""

from __future__ import annotations

import math
import re
import string

#: Fraction of the achievable maximum a value must reach to look generated.
#: Measured against real tokens: random hex, base64 and alphanumeric secrets
#: all sit above 0.9, while words, dates, paths and version strings fall well
#: under 0.7. The gap is wide, so the exact figure matters less than the shape.
ENTROPY_RATIO = 0.75

#: An absolute floor beneath the ratio, so that a very short value over a tiny
#: alphabet cannot clear the bar simply because its ceiling is low too.
MIN_ENTROPY = 2.5

#: Shortest value worth judging. Below this, entropy is noise.
MIN_SECRET_LENGTH = 12

_HEX = set(string.hexdigits)
_ALNUM = set(string.ascii_letters + string.digits)
_BASE64ISH = _ALNUM | set("+/=-_.")

#: Names that promise a credential lives on the other side of the assignment.
SECRET_NAME = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_.\[\]-]*
        (?:passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key|
           private[_-]?key|client[_-]?secret|credential|
           auth[_-]?(?:token|key|secret|pass|pw|header)|authorization|bearer)
     [A-Za-z0-9_.\[\]-]*)
    """
)

_PLACEHOLDER = re.compile(
    r"""(?ix)
    ^(?:
        x{3,} | \*+ | \.+ | -+ |
        (?:change|changeme|placeholder|example|sample|dummy|redacted|removed|
           todo|fixme|none|null|nil|true|false|test|testing|foo|bar|baz)
        [_-]?\w* |
        your[_-]?.* | my[_-]?.* | some[_-]?.* | insert[_-]?.* |
        # Repeated dollars are how Compose escapes interpolation, so
        # "$$(cat /run/secrets/db-password)" is a command, not a credential.
        <.*> | \{\{.*\}\} | \$+\{.*\} | \$+\(.*\) | %\w+% | \$+[A-Za-z_]\w* |
        .*(?:example\.com|localhost|127\.0\.0\.1).*
    )$
    """
)

#: The two filters below that decide on the value's opening character alone.
#: They are named so :func:`looks_like_placeholder` can set them aside for a
#: value that is base64 all the way through, and only those two: every other
#: filter in the list reads the whole value and stays in force.
#:
#: :data:`_EXPRESSION`'s other two alternatives -- a bracket anywhere, an
#: operator between spaces -- cannot match base64 at all, so setting the whole
#: pattern aside costs nothing.
_PATH = re.compile(r"^[~.]{0,2}/[^\s]*$")                  # /etc/ssl/private, ./key.pem
_EXPRESSION = re.compile(r"^[+*/&|!?~]|.*[()\[\]]|.*\s(?:\?\??|&&|\|\||\+)\s")


#: Values that are structure rather than secret: paths, URLs without a
#: password in them, version constraints, dotted identifiers, dates.
_STRUCTURED = (
    _PATH,
    re.compile(r"^[a-z][a-z0-9+.-]*://[^:@\s]*$", re.I),   # a URL carrying no credential
    re.compile(r"^[~^><=v\s]*\d+(?:\.\d+)*(?:[-+][\w.]+)*$", re.I),  # 1.2.3-alpha.4, ^2.0
    re.compile(r"^\d{4}-\d{2}-\d{2}[T \d:.+Z-]*$", re.I),  # timestamps
    re.compile(r"^[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*){2,}$"),  # com.example.thing
    re.compile(r"^[\[{]"),                                # a list or object, not a value
    # A quoted type expression: tuple[int, str, int], dict[str, Node]. Common
    # wherever annotations are strings, and this one caught this project out.
    re.compile(r"^[A-Za-z_][\w.]*\[[^\]]*\]$"),
    # A screaming identifier, snake or kebab: AZURE_FEDERATED_TOKEN_FILE is the
    # name of an environment variable and PRIVATE-TOKEN is the name of an HTTP
    # header. Real tokens in this shape do not exist; they carry mixed case,
    # digits and punctuation.
    re.compile(r"^_?[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)+$"),
    # A snake- or kebab-cased identifier whose words may carry digits:
    # "shared_credentials_2", "password_hash_b64",
    # "pm-27086-update-authentication-apis-for-input-password". A word is
    # letters with digits allowed after them, or a run of digits on its own --
    # a ticket number, which is how bitwarden names every one of its feature
    # flags, thirteen of them under a name with "password" or "key" in it.
    #
    # What makes this safe is not the shape of a word but the separators
    # between them, plus the one capital: a generated credential carries no
    # "-" or "_" at all, and the base64url alphabet that does is random enough
    # that a segment of it has capitals in the middle, which "[A-Z]?[a-z]+"
    # refuses.
    re.compile(
        r"^(?:[A-Z]?[a-z]+[0-9]*|[0-9]{1,6})"
        r"(?:[-_](?:[A-Z]?[a-z]+[0-9]*|[0-9]{1,6}))+$"
    ),
    # Camel or Pascal case with no digits: "ImagePullSecret", "privateToken".
    # Identifiers assigned to identifier-shaped names, which is what a
    # constants file is. A generated credential carries digits or punctuation.
    # An acronym may open or close it: argo-cd assigns the string
    # "SSHPrivateKey" to a field called SSHPrivateKey, and Keycloak assigns
    # "isAccessTokenJWT" to IS_ACCESS_TOKEN_JWT.
    #
    # A hump may also be digits that *begin* a syllable of two letters or more
    # -- "2fa" in bitwarden's "SsoEmail2faSessionToken" -- and that is as far
    # as digits are allowed to go. Three things had to be true at once before
    # that was safe, and the suite names the value that taught each one:
    #
    # * the digits begin a syllable rather than end one, which is what keeps
    #   dagger's password "xFlejaPdjrt25Dvr" reported: there "25" has "Dvr"
    #   after it;
    # * the syllable is two letters or more, and there is at least one
    #   capitalised hump somewhere, which is what keeps a hex string out --
    #   "a3f5c9d1b7e204863f2a" reads as "3f", "5c", "9d" and would otherwise
    #   have been eleven digit-led syllables in a row;
    # * a first draft allowed digits anywhere between the humps, and the
    #   corpus said it took dagger's password with it.
    re.compile(
        r"^(?=.*[A-Z][a-z])(?:[A-Z]{2,}|[A-Za-z][a-z]*)"
        r"(?:[A-Z][a-z]+|\d+[a-z]{2,})+[A-Z]*$"
    ),
    # The same idea with an acronym *between* two humps: Signal-iOS assigns
    # the string "lastKnownWorkingAPNSTokenKey" to a constant called
    # lastKnownWorkingAPNSTokenKey, and "kUDUnrestrictedAccessKey" likewise.
    #
    # A separate pattern rather than a third alternative in the one above,
    # because allowing an interior run of capitals needs every other hump to
    # be a real word -- a capital and *two* or more lower-case letters, not
    # one. Without that the suite's random-token property test found
    # "ntNosjRjMjoZmHghZDXQnzp" in a few hundred tries, which parses as five
    # humps and an acronym and is a generated token. Widening the pattern
    # above instead would have taken that with it.
    re.compile(
        r"^(?=.*[A-Z][a-z])(?:[A-Z]{2,}|[A-Za-z][a-z]*)"
        r"(?:[A-Z][a-z]{2,}|[A-Z]{2,}(?=[A-Z][a-z]))+[A-Z]*$"
    ),
    # A version in the first word and words after it: Keycloak's
    # "oauth2DeviceAuthorizationGrantDisabledMessage". The digits have to be
    # in the *first* word and every later one has to be a capital and two or
    # more lower-case letters, so a run of digits in the middle -- which is
    # what a generated value has -- does not qualify.
    re.compile(r"^[a-z]+\d+(?:[A-Z][a-z]{2,})+$"),
    # One word, hyphenated or not, with the colon a form label carries:
    # "Contrasenya:", "Palavra-passe:", "Adgangskode:". Keycloak's login theme
    # writes console-password in eighty locales and most of them land here.
    re.compile(r"^[A-Za-z][A-Za-z'’]*(?:-[A-Za-z'’]+)*:$"),
    # A URN, or anything else colon-separated and spelled out:
    # "urn:ietf:params:oauth:token-type:jwt", "urn:oasis:names:tc:SAML:1.0:am:password".
    # Identifiers in a specification, which is what an OAuth or SAML constants
    # file is made of, and every one of them ends in a word like "password".
    re.compile(r"^urn:[\w.:+-]+$", re.I),
    re.compile(r"^[A-Za-z][\w.+-]*(?::[A-Za-z0-9][\w.+-]*){2,}$"),
    # Space-separated identifiers: "code id_token token", the OAuth response
    # types. Words with underscores in them, which the prose pattern below
    # does not allow because prose has none.
    re.compile(r"^[a-z][a-z0-9_+-]*(?: +[a-z][a-z0-9_+-]*)+$"),
    # Two identifiers joined by a plus: "dpop+id_token". A media type or a
    # scheme, and never a generated value.
    re.compile(r"^[a-z][a-z0-9_-]*(?:\+[a-z][a-z0-9_-]*)+$"),
    # A Ruby or C++ constant path: "DiscourseAi::Tokenizer::Mistral". The
    # separator is two colons, which no credential format uses.
    re.compile(r"^[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+$"),
    # Hyphenated words in any language: "OAuth-clientgeheim". Letters only --
    # a credential of that length carries digits or punctuation, and a
    # translated label does not.
    re.compile(r"^[A-Za-z]+(?:[-_][A-Za-z]+)+$"),
    # A namespaced key, colon-separated and lowercase, with or without the
    # trailing colon a prefix carries: "user_api_key:device:lock:". Cache and
    # queue keys live in constants whose names end in KEY or TOKEN.
    re.compile(r"^[a-z][\w.-]*(?::[\w.-]+)+:?$"),
    # A modular crypt string: "$2a$10$N9qo8uLOickgx2ZMRZo...", "$argon2id$v=19$...",
    # "$pbkdf2-sha256$i=64000,l=32$". This is the *output* of hashing a
    # password, which is the one thing that cannot be used as one -- and it is
    # what a fixture assigns to a key called password. The prefixes are
    # enumerated rather than matched loosely, because "$something$" is also
    # what a shell writes.
    re.compile(
        r"^\$(?:2[abxy]?|1|5|6|y|7|sha1|md5|argon2[a-z]*|scrypt|bcrypt|"
        r"pbkdf2[\w-]*|s?sha\d*)\$\S*$",
        re.I,
    ),
    # A sentence in any Latin-script language: letters, digits, punctuation,
    # and -- the part that matters -- a space in it. Translated interface
    # strings are assigned to names like password_too_long in every locale a
    # project ships. Without the space requirement this swallows
    # "AdminPassword123!", which is a password ending in punctuation and is
    # exactly the finding a deliberately vulnerable repository is testing for.
    re.compile(r"^(?=[^\W\d_])(?=[^\n]*\s)[\w .,;:!?'’\"()\\/-]+[.!?\":]$"),
    # Words with spaces between them: "shhhh, very secret", "manny is cool",
    # "New Password:". Prose, in other words, which is what a placeholder in an
    # example app looks like, and what a translated interface label is. A
    # generated credential has no spaces in it.
    #
    # One word in the phrase may be a bare version number -- "OAuth 2.0 Device
    # Authorization Grant", a Keycloak label in eighty locales. Only that
    # shape, and not digits anywhere: "Bearer eyJhbGciOiJIUzI1NiI..." is also
    # two words with a space, and is a credential.
    re.compile(
        r"^(?:[A-Za-z][A-Za-z'’.,!?-]*|\d+(?:\.\d+)*)"
        r"(?: +(?:[A-Za-z][A-Za-z'’.,!?-]*|\d+(?:\.\d+)*))+:?$"
    ),
    # An all-lowercase relative path: "testdata/secret_key". Anchored to
    # lowercase on purpose -- a base64 blob containing slashes has mixed case,
    # so this does not swallow one.
    re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9._-]+)+$"),
    # A YAML anchor or alias: "&externalAuthorization", "*externalAuthorization".
    # The value is a name pointing at a block somewhere else in the document.
    re.compile(r"^[&*][A-Za-z_][\w.-]*$"),
    # A lowercase dotted name: "tracing.yaml", "example.internal",
    # "com.example.app". Filenames turn up constantly on the right of a key
    # ending in "secret" or "key", and none of them is a credential.
    re.compile(r"^[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]{1,8})+$"),
    # A query or selector expression: "type!=kubernetes.io/dockercfg,type!=x".
    # Comparison operators do not appear in credentials; they appear in filters.
    re.compile(r".*(?:!=|==|>=|<=).*$"),
    # A reference to where the value lives, rather than the value:
    # "env:NPM_TOKEN", "vault:secret/data/ci", "classpath:server.key". The
    # scheme-with-slashes form is already covered by the URL pattern above;
    # this is the bare one, which CLI tools use precisely so that the
    # credential does not appear in the command line, and which Spring uses to
    # say where a key file is -- private-key: classpath:test.key names a file,
    # and spring-boot writes that a dozen times.
    re.compile(
        r"^(?:env|vault|secret|file|cmd|op|ssm|keyring|classpath|optional|"
        r"resource|jar|bundle):[\w./:@+-]*$",
        re.I,
    ),
    # A fragment of code: `+fmt.Sprintf(` picked up where a name inside one
    # string literal meets a value inside the next, `!areAllCredentialsSet` or
    # `item.credentials ?? []` in a template binding, `access_token=' +` where
    # a string is being concatenated, `--password='.$connection[` where PHP is
    # building one. Brackets and operators do not appear in credentials; they
    # appear in expressions.
    # (The filters are applied with match(), so anything that asks "does this
    # contain" says so with a leading .* -- as the comparison pattern below
    # already does.)
    _EXPRESSION,
    # A sentinel constant, which by convention starts where an identifier
    # cannot: "__n8n_BLANK_VALUE_e5362baf-...". Credentials do not.
    re.compile(r"^__"),
    # A dollar-prefixed dotted reference: API Gateway selects an API key with
    # "$request.header.x-api-key" or "$context.authorizer.usageIdentifierKey",
    # and terraform-provider-aws asserts on both. The dot is what makes this
    # safe next to the shouted "$NAME" rule above -- a password may open with
    # a dollar, but not with a dollar and a dotted path of word characters.
    re.compile(r"^\$[A-Za-z_][\w-]*(?:\.[\w-]+)+$"),
    # A reference into a document: "#/components/schemas/PasswordChallenge".
    # An OpenAPI schema is tens of thousands of these, and the ones that end in
    # a word like "Challenge" or "Token" are the ones a secret rule reads.
    re.compile(r"^#/[\w./~%{}-]+$"),
    # A lowercase dotted identifier with no digits: "git.authheadersecret".
    # Constants files are full of these, and a constant whose *name* ends in
    # "secret" is still a name.
    re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$"),
    # The same thing with camel-case after the dots, which is what an Android
    # preference key looks like: Signal assigns "backup.mediaCredentials" to a
    # constant called KEY_MEDIA_CREDENTIALS, and six more like it in one file.
    # Two dotted segments is fewer than the reverse-DNS filter above wants, so
    # the humps have to carry the argument instead: every one is a capital and
    # two or more lower-case letters, which a base64 run is not -- a JWT's
    # middle segment "eyJzdWIiOiJhYmMxMjM0NTY3ODkifQ" breaks apart on the very
    # first hump.
    re.compile(
        r"^[a-z][a-z0-9]*(?:[A-Z][a-z]{2,}[0-9]*)*"
        r"(?:\.[a-z][a-z0-9]*(?:[A-Z][a-z]{2,}[0-9]*)*)+$"
    ),
    # Words joined by hyphens or underscores: "unstructured", "content-type",
    # "Proxy-Authorization". Generated credentials carry digits
    # or mixed case; a pure word-list slug is vocabulary. The cost is that a
    # deliberate passphrase secret goes unreported, which is a trade worth
    # making -- this pattern is most of what a real codebase assigns to names
    # like token_type and auth_scheme.
    re.compile(r"^[A-Z]?[a-z]+(?:[-_][A-Z]?[a-z]+)*$"),
)

# One arm of a quoted type union. Splitting on ``|`` first keeps matching
# linear: allowing spaces both inside an arm and around the delimiter in one
# repeated regex can create catastrophic backtracking on a rejected string.
_TYPE_UNION_ARM = re.compile(r"^[A-Za-z_][\w.\[\], ]*$")


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Random base64 lands near 6, English near 4."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def alphabet_size(value: str) -> int:
    """The nominal size of the alphabet ``value`` appears to be drawn from.

    Nominal rather than observed: a 16-character hex token uses at most 16
    distinct characters however random it is, and judging it against its own
    observed alphabet would make every string look maximally random.
    """
    chars = set(value)
    if chars <= set(string.digits):
        return 10
    if chars <= _HEX:
        return 16
    if chars <= set(string.ascii_lowercase + string.digits + "_-"):
        return 38
    if chars <= set(string.ascii_uppercase + string.digits + "_-"):
        return 38
    if chars <= _ALNUM:
        return 62
    if chars <= _BASE64ISH:
        return 68
    return 90


#: What each class in :func:`alphabet_size` is called, in its order. The name
#: and the number have to come from one decision: a caller that rebuilt these
#: sets to name them got "aA1" as 16 symbols described as "letters and digits",
#: because its hex set was lowercase only.
_ALPHABET_NAMES = (
    (set(string.digits), 10, "digits"),
    (_HEX, 16, "hex"),
    (set(string.ascii_lowercase + string.digits + "_-"), 38,
     "lowercase, digits, dash and underscore"),
    (set(string.ascii_uppercase + string.digits + "_-"), 38,
     "uppercase, digits, dash and underscore"),
    (_ALNUM, 62, "letters and digits"),
    (_BASE64ISH, 68, "base64"),
)


def alphabet_name(value: str) -> str:
    """What to call the alphabet :func:`alphabet_size` counted."""
    chars = set(value)
    for alphabet, _, name in _ALPHABET_NAMES:
        if chars <= alphabet:
            return name
    return "mixed, including punctuation"


def entropy_floor(value: str) -> float:
    """The entropy ``value`` must reach for its length and alphabet to look generated.

    The ceiling for a string of length *n* over an alphabet of *k* symbols is
    ``log2(min(k, n))`` -- capped by *n* because a string cannot use more
    distinct symbols than it has characters. A credential sits near that
    ceiling; a word or a version number does not.
    """
    if not value:
        return MIN_ENTROPY
    ceiling = math.log2(min(alphabet_size(value), len(value)))
    return max(MIN_ENTROPY, ENTROPY_RATIO * ceiling)


#: Interpolation anywhere in a value, not only at its start:
#: ``"GITHUB_TOKEN_${org^^}"`` is a variable name being assembled.
#: A value with a brace-delimited placeholder in it: "${VAR}", "{{ x }}",
#: "%{count}", "#{Rails.env}", "Bearer {env:TOKEN}". Credentials have no
#: braces in them, so the last of these is as safe as the rest -- including
#: the empty pair Python's own format strings use, which is how Azure's
#: examples write "SharedKey {}:{}" and assign it to ``authorization``.
#:
#: A bare "$NAME" counts too, where the name is shouted: that is shell, and
#: "multiplier@https://$KV_NAME.vault.azure.net" is a Key Vault reference in
#: an Azure example rather than the secret it points at. Shouted because a
#: lower-case "$" run is what a bcrypt hash and a stray dollar in a password
#: both look like.
_EMBEDDED_INTERPOLATION = re.compile(
    r"\$\{|\$\(|\{\{|%\(|%\{|#\{|\{[^\s{}]{0,64}\}|\$[A-Z][A-Z0-9_]+"
)

#: An angle-bracket placeholder anywhere in a value: "glrt-<TOKEN>" is what
#: documentation writes where a real token will go.
_ANGLE_PLACEHOLDER = re.compile(r"<[A-Za-z_][\w .-]*>")


#: Base64 over its whole length, padding included. Used only to decide whether
#: a leading "/" or "+" is structure or coincidence.
_BASE64_ALPHABET = re.compile(r"[A-Za-z0-9+/]+={0,2}$")

#: The filters set aside for a base64 blob, and the list without them. The
#: second is built once rather than filtered on every call.
_LEADING_PUNCTUATION = (_PATH, _EXPRESSION)
_INTERIOR_STRUCTURE = tuple(
    pattern for pattern in _STRUCTURED if pattern not in _LEADING_PUNCTUATION
)


def _is_base64_blob(value: str) -> bool:
    """True when ``value`` is base64 all the way through and long enough to be a key.

    Base64's alphabet contains "+" and "/", so roughly one generated value in
    thirty-two opens with a character :data:`_STRUCTURED` otherwise reads as
    structure: a leading "/" is a filesystem path and a leading "+" the start
    of an expression. Plausible commits a 64-character ``SECRET_KEY_BASE`` into
    four ``.env`` files and it opens with "/", which is the whole reason it was
    not reported.

    What keeps a real path out is the length of the runs between the slashes:
    every one has to be at least as long as the shortest thing this module will
    call a credential, so "/etc/ssl/private" is three short words and stays a
    path. A key is one long run, or a few.
    """
    if _BASE64_ALPHABET.fullmatch(value) is None:
        return False
    return all(
        len(segment) >= MIN_SECRET_LENGTH for segment in value.split("/") if segment
    )


def looks_like_placeholder(value: str) -> bool:
    """True when a value is obviously a stand-in rather than a real credential."""
    stripped = value.strip()
    if not stripped or _PLACEHOLDER.match(stripped):
        return True
    if _EMBEDDED_INTERPOLATION.search(stripped) or _ANGLE_PLACEHOLDER.search(stripped):
        return True
    # Python forward annotations such as "Secret | None" and
    # "dict[str, Node] | None" are type expressions, not credentials.
    type_arms = stripped.split("|")
    if len(type_arms) > 1 and all(
        _TYPE_UNION_ARM.fullmatch(arm.strip()) for arm in type_arms
    ):
        return True
    structure = _INTERIOR_STRUCTURE if _is_base64_blob(stripped) else _STRUCTURED
    if any(pattern.match(stripped) for pattern in structure):
        return True
    # A comma-separated list of things that are each structure is a list.
    # Bitwarden passes "BW-GHAPP-ID,BW-GHAPP-KEY" to a key-vault action in
    # three workflows: two names of secrets, under a key called "secrets".
    # No credential contains a comma, so this asks the question once and does
    # not recurse.
    parts = [part.strip() for part in stripped.split(",")]
    if len(parts) > 1 and all(
        part and any(pattern.match(part) for pattern in _STRUCTURED) for part in parts
    ):
        return True
    # "aaaaaaaaaaaa" and friends: one repeated character is nobody's password.
    return len(set(stripped)) <= 2


#: Words that turn a credential-ish name into a label for one. "credentialType"
#: holds the name of a credential kind, "secretName" the name of a Kubernetes
#: Secret, "tokenPattern" a regular expression -- none of them holds the thing
#: itself. Measured on n8n, whose nodes assign a credential *type* to a key
#: called credentialType seven hundred times over.
#:
#: "header" is deliberately absent: an auth header's value is the credential.
_LABEL_SUFFIXES = (
    "type", "types", "kind", "kinds", "name", "names", "field", "fields",
    "label", "labels", "prefix", "suffix", "pattern", "patterns",
    "placeholder", "example", "format", "scheme", "column", "table",
    # Words that make the value prose *about* a credential. A translated
    # interface is the largest source of these: Keycloak assigns an English
    # sentence to oauthDeviceAuthorizationGrantHelp once per locale, and it
    # ships eighty-odd locales.
    "help", "description", "desc", "error", "message", "text", "title",
    "tooltip", "tip", "note",
)


#: The same words again, asked of the whole identifier rather than its tail,
#: and read as words rather than as letters. ``COOKIE_NAME_ACCESS_TOKEN`` is
#: the name of the cookie the access token travels in, not the token, and the
#: suffix test cannot see that because the label word is in the middle. Home
#: Assistant has four of these in shipped source.
#:
#: "example" is deliberately absent, and is the reason this is a second list
#: rather than the first one reused: a name ending in "example" is a specimen,
#: but ``EXAMPLE_API_TOKEN`` in the middle of a settings file may well hold a
#: real value that somebody pasted in, and that is a finding worth keeping.
_LABEL_WORDS = frozenset(_LABEL_SUFFIXES) - {"example"}

#: Splits an identifier into the words it was written from: underscores,
#: hyphens, dots and brackets separate, and so does a lower-to-upper hump.
_WORD_BOUNDARY = re.compile(r"[^A-Za-z]+|(?<=[a-z0-9])(?=[A-Z])")


def name_words(name: str) -> "tuple[str, ...]":
    """The lower-case words ``name`` was written from.

    Split before lower-casing, because the hump in ``cookieNameAccessToken`` is
    the only thing marking the boundaries in it.
    """
    return tuple(word.lower() for word in _WORD_BOUNDARY.split(name) if word)


def is_secret_name(name: str) -> bool:
    """True when an identifier announces that its value is a credential."""
    if SECRET_NAME.search(name) is None:
        return False
    trimmed = re.sub(r"[^a-z]", "", name.lower())
    if trimmed.endswith(_LABEL_SUFFIXES):
        return False
    return not _LABEL_WORDS.intersection(name_words(name))


#: How long a run of consecutive characters has to be before it can only be
#: somebody counting. Eight is already one chance in billions for a generated
#: value, and "abcdefgh" or "12345678" is most of what a test fixture, or a
#: character set to generate passwords from, is made of.
SEQUENCE_LENGTH = 8


def is_counted_out(value: str) -> bool:
    """True when part of ``value`` is somebody counting: abcdefgh, 12345678.

    Asked by the provider rules of a value that already has a documented
    shape, and by the entropy rules of one that does not. It is the same
    question both times: a string of consecutive characters measures as
    high-entropy -- every character distinct is the maximum a length can carry
    -- and is the one thing a credential never is.

    Nextcloud generates share passwords from
    ``'abcdefgijkmnopqrstwxyzABCDEFGHJKLMNPQRSTWXYZ23456789'``, assigned to a
    name with "password" in it, and that is what this is for.
    """
    run = 1
    for previous, current in zip(value, value[1:]):
        run = run + 1 if ord(current) - ord(previous) == 1 else 1
        if run >= SEQUENCE_LENGTH:
            return True
    return False


def looks_generated(value: str) -> bool:
    """True when ``value`` is long enough, random enough and not a placeholder.

    The single question every heuristic rule asks. Whether the *name* on the
    other side of the assignment justifies asking it is the caller's problem.
    """
    return entropy_shortfall(value) == 0.0


def entropy_shortfall(value: str) -> "float | None":
    """How many bits ``value`` is short of looking generated, or None.

    ``0.0`` means it reached the floor; a positive number means it failed on
    entropy alone and by how much; ``None`` means it failed for one of the
    reasons that are not a matter of degree, and for which "nearly" means
    nothing:

    * too short -- a six-character value is not a near miss for a credential;
    * not ASCII -- credentials travel through headers, URLs and environment
      variables that are. Text in another script is not, and its entropy is
      high for a reason that has nothing to do with randomness: a larger
      alphabet raises the per-character measure. Measured on Discourse, whose
      translated interface strings produced 1,600 findings -- "password" in
      Arabic, forty times per locale;
    * a placeholder -- ``<YOUR_TOKEN_HERE>`` fails on purpose and no amount of
      entropy would make it a credential;
    * counted out -- ``abcdefgh`` measures as maximally random for its length
      and is the one thing a credential never is.
    """
    stripped = value.strip()
    if len(stripped) < MIN_SECRET_LENGTH:
        return None
    if not stripped.isascii():
        return None
    if looks_like_placeholder(stripped):
        return None
    if is_counted_out(stripped):
        return None
    return max(0.0, entropy_floor(stripped) - shannon_entropy(stripped))
