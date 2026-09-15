"""The judgement calls: entropy, placeholders, and secret-shaped names."""

import unittest

from bluerayscan import heuristics, wellknown


class TestEntropy(unittest.TestCase):
    def test_empty_string_has_no_entropy(self):
        self.assertEqual(heuristics.shannon_entropy(""), 0.0)

    def test_repeated_character_has_no_entropy(self):
        self.assertEqual(heuristics.shannon_entropy("aaaaaaaa"), 0.0)

    def test_english_prose_scores_below_a_generated_token(self):
        prose = heuristics.shannon_entropy("the quick brown fox")
        token = heuristics.shannon_entropy("aG9sZFRoZUxpbmVYeVo5")
        self.assertLess(prose, token)


class TestEntropyFloor(unittest.TestCase):
    """The floor has to move with the alphabet, or it is wrong twice over."""

    def test_alphabet_is_judged_nominally_not_by_observation(self):
        self.assertEqual(heuristics.alphabet_size("0123456789abcdef"), 16)
        self.assertEqual(heuristics.alphabet_size("Xk92mQp7Lz4TvB8n"), 62)
        self.assertEqual(heuristics.alphabet_size("0123456789"), 10)

    def test_hex_token_clears_its_own_floor(self):
        # A 16-character hex token cannot exceed 4.0 bits, so the old flat 3.2
        # bar left almost no room between a real token and a hand-typed one.
        token = "a3f5c9d1b7e20486"
        self.assertLess(heuristics.entropy_floor(token), 3.2)
        self.assertTrue(heuristics.looks_generated(token))

    def test_base64_blob_is_held_to_a_higher_floor_than_hex(self):
        self.assertGreater(
            heuristics.entropy_floor("aG9sZFRoZUxpbmVYeVo5cXc4bTJrN3A1" * 4),
            heuristics.entropy_floor("a3f5c9d1b7e20486"),
        )

    def test_floor_never_falls_below_the_absolute_minimum(self):
        self.assertGreaterEqual(heuristics.entropy_floor("abc"), heuristics.MIN_ENTROPY)


class TestLooksGenerated(unittest.TestCase):
    def test_accepts_a_random_token(self):
        self.assertTrue(heuristics.looks_generated("Xk92mQp7Lz4TvB8nRw1Y"))

    def test_rejects_a_short_value(self):
        self.assertFalse(heuristics.looks_generated("Xk92mQp7"))

    def test_rejects_placeholders(self):
        for value in (
            "your-password-here",
            "${DB_PASSWORD}",
            "$DATABASE_URL",
            "changeme-please",
            "xxxxxxxxxxxxxxxx",
            "<your-token-here>",
        ):
            with self.subTest(value=value):
                self.assertFalse(heuristics.looks_generated(value))

    def test_rejects_structure_that_is_not_a_credential(self):
        for value in (
            "/etc/ssl/private/server.pem",
            "https://api.internal.example/v1",
            "1.2.3-alpha.4",
            "2024-01-02T03:04:05Z",
            "com.example.service.auth",
            "[{ name = 'someone' }]",
            # Vocabulary, not entropy. Every one of these was a real false
            # positive from a run over the Python standard library, assigned
            # to a name like token_type or auth_header.
            "unstructured",
            "bare-quoted-string",
            "Proxy-Authorization",
            "obs-local-part",
            # A quoted type alias, which is what a module full of string
            # annotations assigns to names like Token and Block.
            "tuple[int, str, int]",
            "dict[str, Node]",
            # Each of these was a real false positive, measured against the
            # Prometheus repository: a variable name being assembled, the name
            # of an environment variable, and a relative path.
            "GITHUB_TOKEN_${org^^}",
            "AZURE_FEDERATED_TOKEN_FILE",
            "testdata/secret_key",
            # From a Helm chart repository: a YAML anchor, an alias, a label
            # selector, and a filename on the right of a key called "secret".
            "&externalAuthorization",
            "*externalAuthorization",
            "type!=kubernetes.io/dockercfg,type!=helm.sh/release.v1",
            "tracing.yaml",
            # From the GitLab runner: an HTTP header name, a placeholder in
            # documentation, and a constant holding a Kubernetes type name.
            "PRIVATE-TOKEN",
            "glrt-<TOKEN>",
            "ImagePullSecret",
            # From the Express examples: what a placeholder in a sample app
            # actually looks like.
            "shhhh, very secret",
            "manny is cool",
            # From Dagger: a reference saying where the credential lives
            # rather than what it is, a string annotation in a generated
            # client, a fragment of Go picked up between two string literals,
            # and a constant whose name -- not value -- ends in "secret".
            "env:CARGO_REGISTRY_TOKEN",
            "vault:secret/data/ci",
            # From Spring Boot, whose configuration says where a key file is
            # rather than what is in it.
            "classpath:org/springframework/boot/server.key",
            "optional:classpath:application-test.properties",
            "Secret | None",
            "list[Secret] | None",
            "dict[str, Node]|Secret|None",
            "+fmt.Sprintf(",
            "git.authheadersecret",
            # From authentik: identifiers out of a specification, which is
            # what an OAuth or SAML constants file is made of -- and every one
            # of them ends in a word like "password" or "token".
            "urn:ietf:params:oauth:token-type:jwt",
            "urn:oasis:names:tc:SAML:1.0:am:password",
            "code id_token token",
            "dpop+id_token",
            "authentik_policies_password.passwordpolicy",
            "#/components/schemas/PasswordChallenge",
            # From n8n: a template binding, a nullish coalescing expression,
            # a string being concatenated, a sentinel constant, and a table
            # name in a migration.
            "!areAllCredentialsSet",
            "item.credentials ?? []",
            "__n8n_BLANK_VALUE_e5362baf-c777-4d57",
            # From the Laravel framework: PHP building a command line out of
            # a configuration array.
            "--password='.$connection[",
            "shared_credentials_2",
            # From Discourse: a translated interface string, a Ruby constant
            # path, a Redis key prefix, a hyphenated label, a modular crypt
            # identifier, and an environment variable name with a private
            # prefix. Every one of them assigned to a name with "password" or
            # "token" in it.
            "Wachtwoorden mogen maximaal 200 tekens lang zijn.",
            "DiscourseAi::Tokenizer::Mistral",
            "user_api_key:device:lock:",
            "OAuth-clientgeheim",
            "$pbkdf2-sha256$i=64000,l=32$",
            # A password hash is the output of hashing a password, which is
            # the one thing that cannot be used as one. n8n's fixtures assign
            # these to keys called password.
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
            "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub",
            "_DISCOURSE_USER_TOKEN",
            # From keycloak/keycloak: a login theme translated into eighty
            # locales, where the label carries the colon a form field wants,
            # and an admin console string with a version number in it. The
            # existing prose patterns wanted a full stop at the end and every
            # word to start with a letter.
            "New Password:",
            "Contrasenya:",
            "Palavra-passe:",
            "OAuth 2.0 Device Authorization Grant",
            # And a constants file assigning each constant its own name in
            # another casing. From keycloak and from argo-cd, whose
            # repository_secrets_test.go sets SSHPrivateKey to "SSHPrivateKey".
            "SSHPrivateKey",
            "isAccessTokenJWT",
            "oauth2DeviceAuthorizationGrantDisabledMessage",
        ):
            with self.subTest(value=value):
                self.assertFalse(heuristics.looks_generated(value))

    def test_rejects_a_repeated_pair(self):
        self.assertFalse(heuristics.looks_generated("ababababababab"))

    def test_type_union_filter_rejects_a_long_non_type_without_backtracking(self):
        value = "A |" * 10_000 + "!"
        self.assertFalse(heuristics.looks_like_placeholder(value))


class TestValuesThatSurviveTheFilters(unittest.TestCase):
    """The filters must not swallow the things they sit next to."""

    def test_a_generated_password_reads_as_humps_and_is_still_reported(self):
        # From dagger: registryPassword = "xFlejaPdjrt25Dvr". A first draft of
        # the identifier filter allowed digits between the humps, and this is
        # what the corpus said about that. The second is the fixture password
        # the shell rules are tested with, and the third is named in the
        # prose filter's own comment as the thing it must not swallow.
        for value in ("xFlejaPdjrt25Dvr", "Qq7Zx9Lm2Pv4Rt8W", "AdminPassword123!"):
            with self.subTest(value=value):
                self.assertTrue(heuristics.looks_generated(value))

    def test_a_bearer_token_is_two_words_with_a_space_and_still_a_credential(self):
        # The prose filter lets one word of a phrase be a version number.
        # "Bearer <jwt>" is also two tokens with a space between them.
        value = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        self.assertFalse(heuristics.looks_like_placeholder(value))

    def test_an_uppercase_key_without_underscores_is_still_a_key(self):
        # AZURE_FEDERATED_TOKEN_FILE is an identifier; A1B2C3D4E5F6G7H8I9J0 is
        # an access key, and they differ only by punctuation.
        self.assertTrue(heuristics.looks_generated("A1B2C3D4E5F6G7H8I9J0"))
        self.assertTrue(heuristics.looks_generated("SCW0W8NG6024YHRJ7723"))

    def test_a_password_ending_in_punctuation_is_not_prose(self):
        # The prose filter wants a space in it. Without that requirement it
        # swallows this, which is the finding terragoat exists to produce.
        self.assertTrue(heuristics.looks_generated("AdminPassword123!"))
        self.assertTrue(heuristics.looks_generated("Sup3rS3cretPassw0rd."))

    def test_text_in_another_script_is_not_measured_for_entropy(self):
        # A larger alphabet raises entropy per character for a reason that has
        # nothing to do with randomness. Credentials are ASCII; they travel
        # through headers and environment variables that are.
        self.assertFalse(heuristics.looks_generated("كلمة المرور غير صحيحة."))
        self.assertFalse(heuristics.looks_generated("パスワードが正しくありません"))

    def test_a_credential_that_happens_to_start_with_a_word_is_kept(self):
        # The reference filter is anchored to a scheme and a colon; a token
        # beginning with letters is not a reference.
        self.assertTrue(heuristics.looks_generated("envXk92mQp7Lz4TvB8nRw1Y"))
        self.assertTrue(heuristics.looks_generated("secret-Xk92mQp7Lz4TvB8n"))

    def test_a_base64_blob_with_slashes_is_not_read_as_a_path(self):
        self.assertTrue(heuristics.looks_generated("aG9sZFRoZUxpbmVYeVo5/cXc4bTJrN3A1"))

    def test_a_base64_blob_that_opens_with_a_slash_is_not_read_as_a_path(self):
        # Plausible commits this SECRET_KEY_BASE into four .env files under
        # config/. Base64's alphabet contains "/", so one generated value in
        # thirty-two opens with one, and the path filter took this whole class
        # on that single character.
        value = "/njrhntbycvastyvtk1zycwfm981vpo/0xrvwjjvemdakc/vsvbrevlwsc6u8rcg"
        self.assertTrue(heuristics.looks_generated(value))

    def test_a_real_path_is_still_a_path(self):
        # The guard is the length of the runs between the slashes: a path is
        # short words, a key is one long run or a few.
        for value in ("/etc/ssl/private", "./key.pem", "/usr/bin/env",
                      "/home/runner/work/repo/repo"):
            with self.subTest(value=value):
                self.assertTrue(heuristics.looks_like_placeholder(value))

    def test_a_hex_string_does_not_read_as_digit_led_syllables(self):
        # "a3f5c9d1b7e204863f2a" is the private_key_id in this suite's own
        # service-account fixture. It breaks into "3f", "5c", "9d" and a first
        # draft of the digit-led syllable read all eleven of them as an
        # identifier, which turned SEC021 off.
        self.assertTrue(heuristics.looks_generated("a3f5c9d1b7e204863f2a"))

    def test_a_list_of_credentials_is_still_a_list_of_credentials(self):
        # The comma filter asks whether every part is structure. One real key
        # among them and the answer is no.
        value = "BW-GHAPP-ID,xFlejaPdjrt25Dvr"
        self.assertFalse(heuristics.looks_like_placeholder(value))


class TestIdentifiersFromRoundFour(unittest.TestCase):
    """Values bitwarden assigns to names with "password" or "key" in them."""

    def test_a_feature_flag_slug_carries_a_ticket_number(self):
        # src/Core/Constants.cs, thirteen of them. The slug filter allowed a
        # word to carry at most two trailing digits and a bare run of at most
        # four, and a ticket number is five.
        for value in (
            "pm-27086-update-authentication-apis-for-input-password",
            "pm-31088-master-password-service-emit-salt",
            "pm-27581-device-auth-key",
            "enable-account-encryption-v2-jit-password-registration",
        ):
            with self.subTest(value=value):
                self.assertTrue(heuristics.looks_like_placeholder(value))

    def test_a_slug_word_may_be_one_letter_and_digits(self):
        # src/Identity/.../SendAccess/SendAccessConstants.cs: "b64" is a word
        # in this vocabulary, and it is one letter followed by two digits.
        for value in ("password_hash_b64", "password_hash_b64_invalid",
                      "password_hash_b64_required"):
            with self.subTest(value=value):
                self.assertTrue(heuristics.looks_like_placeholder(value))

    def test_two_secret_names_in_one_string_are_two_names(self):
        # Three bitwarden workflows pass this to a key-vault action under a
        # key called "secrets". Both halves are names of secrets; neither is
        # a secret.
        self.assertTrue(heuristics.looks_like_placeholder("BW-GHAPP-ID,BW-GHAPP-KEY"))

    def test_digits_may_begin_a_syllable_in_an_identifier(self):
        # src/Core/Auth/.../SsoEmail2faSessionTokenable.cs assigns this string
        # to a constant called TokenIdentifier, which is what it is.
        self.assertTrue(heuristics.looks_like_placeholder("SsoEmail2faSessionToken"))
        self.assertTrue(
            heuristics.looks_like_placeholder("SsoEmail2faSessionTokenDataProtector")
        )


class TestIdentifiersFromRoundFive(unittest.TestCase):
    """Values from Signal-Android and Azure's machine-learning examples."""

    def test_a_dotted_camel_case_preference_key_is_a_key_name(self):
        # app/src/main/java/.../keyvalue/BackupValues.kt assigns these to
        # constants called KEY_MEDIA_CREDENTIALS and friends, seven in one
        # file. Two dotted segments is one fewer than the reverse-DNS filter
        # wants, so the humps carry the argument instead.
        for value in ("backup.mediaCredentials", "backup.restoreState",
                      "backup.messageCdnReadCredentialsTimestamp"):
            with self.subTest(value=value):
                self.assertTrue(heuristics.looks_like_placeholder(value))

    def test_a_base64_run_is_not_a_dotted_identifier(self):
        # A JWT is three dotted segments of base64 and must stay reportable;
        # the middle one here breaks apart on its very first hump.
        self.assertTrue(heuristics.looks_generated("dozjgNryP4J3jVmNHl0w5N"))

    def test_an_empty_format_placeholder_is_still_a_placeholder(self):
        # setup/setup-ci/security-scanner/amlsecscan.py builds an
        # Authorization header this way and assigns it to "authorization".
        self.assertTrue(heuristics.looks_like_placeholder("SharedKey {}:{}"))

    def test_a_shouted_shell_variable_anywhere_is_interpolation(self):
        # cli/deploy-moe-keyvault.sh: a Key Vault reference, not the secret
        # it points at.
        value = "multiplier@https://$KV_NAME.vault.azure.net"
        self.assertTrue(heuristics.looks_like_placeholder(value))

    def test_a_dollar_in_a_password_is_not_a_variable(self):
        # Shouted is the requirement: a bcrypt hash and a stray dollar in a
        # password both put lower-case after the "$".
        self.assertTrue(heuristics.looks_generated("Tr0ub4dor$three3more"))


class TestIdentifiersFromRoundSix(unittest.TestCase):
    """Constants in Signal-iOS whose value is the constant's own name."""

    def test_an_acronym_may_sit_between_two_humps(self):
        # SignalServiceKit/Util/APNSRotationStore.swift and
        # Messages/UD/OWSUDManager.swift. Round three handled an acronym at
        # either end; the middle is where Apple's vocabulary puts them.
        for value in ("kUDUnrestrictedAccessKey", "lastKnownWorkingAPNSTokenKey",
                      "lastKnownWorkingAPNSTokenTimestampKey"):
            with self.subTest(value=value):
                self.assertTrue(heuristics.looks_like_placeholder(value))

    def test_a_generated_token_does_not_parse_as_an_acronym(self):
        # The suite's random-token property test found this in a few hundred
        # tries against a first draft that allowed an interior acronym in the
        # existing pattern: it parses as five humps and an acronym. Requiring
        # every other hump to be a capital and *two* lower-case letters is
        # what separates them.
        self.assertTrue(heuristics.looks_generated("ntNosjRjMjoZmHghZDXQnzp"))

    def test_a_real_key_in_the_same_file_is_still_reported(self):
        # SignalServiceKit/Network/API/Giphy/GiphyAPI.swift assigns this to
        # kGiphyApiKey, three lines from one of the constants above.
        self.assertTrue(heuristics.looks_generated("ZsUpUm2L6cVbvei347EQNp7HrROjbOdc"))


class TestReferencesFromRoundSeven(unittest.TestCase):
    def test_a_dollar_prefixed_dotted_reference_is_a_reference(self):
        # API Gateway selects an API key with these, and
        # terraform-provider-aws asserts on both. Argo CD's own manual writes
        # "$dex.github.clientSecret" as the documented way to point at a
        # secret, and was told it had leaked one.
        for value in ("$request.header.x-api-key",
                      "$context.authorizer.usageIdentifierKey",
                      "$dex.github.clientSecret", "$secrets.oldKey"):
            with self.subTest(value=value):
                self.assertTrue(heuristics.looks_like_placeholder(value))


class TestRecallFromLeakyRepo(unittest.TestCase):
    """Values a repository built to hold secrets said nothing about."""

    def test_a_uuid_is_generated_by_definition(self):
        # npm's classic auth token is a UUID and nothing else. Hex with four
        # hyphens in it lands about a sixth of a bit under the floor, every
        # time, so the floor alone could never report one.
        self.assertTrue(heuristics.looks_generated("26dfe8d8-889b-4380-92ff-9c3c6ea5d930"))

    def test_the_name_is_still_the_gate_for_one(self):
        # "client_id" is the identifier that is usually a UUID and usually
        # public. It does not promise a credential, so nothing asks.
        self.assertFalse(heuristics.is_secret_name("client_id"))

    def test_a_word_with_trailing_digits_is_part_of_a_phrase(self):
        # n8n's interface: "Connect OAuth2 Credential". The phrase filter let
        # a bare version number be a word but not a word carrying one, so
        # thirteen translated labels in discourse were reported at medium.
        for value in ("Connect OAuth2 Credential", "Custom OAuth2",
                      "Default - None", "Token URL for OAuth2"):
            with self.subTest(value=value):
                self.assertTrue(heuristics.looks_like_placeholder(value))

    def test_a_bearer_token_is_still_two_words_and_still_a_credential(self):
        value = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        self.assertFalse(heuristics.looks_like_placeholder(value))

    def test_a_path_under_a_shouted_directory_is_a_path(self):
        # gh's tests expect "tokenSource":"GH_CONFIG_DIR/hosts.yml".
        self.assertTrue(heuristics.looks_like_placeholder("GH_CONFIG_DIR/hosts.yml"))


class TestTestPaths(unittest.TestCase):
    def test_fixture_trees_and_test_files_are_recognised(self):
        for path in (
            "config/testdata/conf.yml",
            "discovery/vultr/mock_test.go",
            "tests/fixtures/key.pem",
            "spec/support/thing.rb",
        ):
            with self.subTest(path=path):
                self.assertTrue(wellknown.is_test_path(path))

    def test_a_fixture_directory_is_written_four_ways(self):
        # terraform-provider-aws uses "test-fixtures" throughout, and the list
        # knew only "fixtures" and "__fixtures__". The separators are what
        # differ, so they are taken out before the comparison.
        for path in (
            "internal/service/rds/test-fixtures/stack.json",
            "internal/service/transfer/test_fixtures/key",
            "pkg/testfixtures/response.json",
            "pkg/test-data/response.json",
        ):
            with self.subTest(path=path):
                self.assertTrue(wellknown.is_test_path(path))

    def test_a_directory_that_merely_starts_with_test_is_not(self):
        for path in ("build/test-results/report.xml", "src/testbed/main.go"):
            with self.subTest(path=path):
                self.assertFalse(wellknown.is_test_path(path))

    def test_ordinary_source_is_not(self):
        for path in ("src/app/main.go", "cmd/server/config.py", "latest/index.html"):
            with self.subTest(path=path):
                self.assertFalse(wellknown.is_test_path(path))


class TestNamesThatAreLabels(unittest.TestCase):
    """A name for a credential is not a name holding one."""

    def test_a_label_suffix_ends_the_question(self):
        for name in (
            "credentialType", "secretName", "tokenPattern", "password_field",
            "apiKeyPlaceholder", "secret_table", "AUTH_TOKEN_FORMAT",
        ):
            with self.subTest(name=name):
                self.assertFalse(heuristics.is_secret_name(name))

    def test_a_label_word_in_the_middle_ends_it_too(self):
        # From home-assistant/core:
        # components/keycloak/auth_manager/constants.py, where
        # COOKIE_NAME_ACCESS_TOKEN = "_access_token" names the cookie the
        # token travels in. The suffix test cannot see a label word that is
        # not the last one.
        for name in (
            "COOKIE_NAME_ACCESS_TOKEN", "cookieNameAccessToken",
            "SECRET_NAME_OVERRIDE", "token_field_index", "apiKeyLabelText",
        ):
            with self.subTest(name=name):
                self.assertFalse(heuristics.is_secret_name(name))

    def test_a_name_holding_text_about_a_credential(self):
        # From keycloak/keycloak's admin console messages, one per locale:
        # oauthDeviceAuthorizationGrantHelp holds a paragraph explaining the
        # grant. So do the Error, Description and Tooltip families beside it.
        for name in (
            "oauthDeviceAuthorizationGrantHelp",
            "STS_COMBINED_SECRET_KEY_ERROR",
            "tokenDescription",
            "apiKeyTooltip",
            "password_help_text",
        ):
            with self.subTest(name=name):
                self.assertFalse(heuristics.is_secret_name(name))

    def test_a_label_word_only_counts_as_a_whole_word(self):
        # "namespace" is not "name", and NAMESPACE_TOKEN holds a token.
        for name in ("NAMESPACE_TOKEN", "username_password", "typedSecret"):
            with self.subTest(name=name):
                self.assertTrue(heuristics.is_secret_name(name))

    def test_example_is_a_suffix_and_not_a_middle_word(self):
        # A name ending in "example" is a specimen. EXAMPLE_API_TOKEN in the
        # middle of a settings file may well hold a value somebody pasted in,
        # and losing that is worse than reporting it.
        self.assertFalse(heuristics.is_secret_name("api_key_example"))
        self.assertTrue(heuristics.is_secret_name("EXAMPLE_API_TOKEN"))

    def test_the_names_that_do_hold_one_are_untouched(self):
        for name in (
            "password", "api_key", "AUTH_TOKEN", "client_secret", "authHeader",
            "authorization", "privateKey",
        ):
            with self.subTest(name=name):
                self.assertTrue(heuristics.is_secret_name(name))

    def test_the_words_a_name_was_written_from(self):
        self.assertEqual(
            heuristics.name_words("COOKIE_NAME_ACCESS_TOKEN"),
            ("cookie", "name", "access", "token"),
        )
        self.assertEqual(
            heuristics.name_words("props[apiKey]"), ("props", "api", "key")
        )


class TestSecretNames(unittest.TestCase):
    def test_recognises_credential_names(self):
        for name in ("api_key", "DB_PASSWORD", "clientSecret", "_authToken", "AUTHORIZATION"):
            with self.subTest(name=name):
                self.assertTrue(heuristics.is_secret_name(name))

    def test_does_not_read_authors_as_auth(self):
        # The bare substring "auth" appears in authors, authorized_keys and
        # authenticate, none of which hold a credential. This exact false
        # positive fired on this project's own pyproject.toml.
        for name in ("authors", "author", "authorized_keys", "authenticate"):
            with self.subTest(name=name):
                self.assertFalse(heuristics.is_secret_name(name))


class TestCountedOut(unittest.TestCase):
    """A run of consecutive characters is the one thing a credential never is."""

    def test_a_character_set_is_not_a_credential(self):
        # From nextcloud/server: apps/files_sharing/src/utils/GeneratePassword.ts
        # holds the alphabet it generates share passwords from, assigned to a
        # name with "password" in it. Every character distinct is the most
        # entropy a length can carry, which is why it read as generated.
        value = "abcdefgijkmnopqrstwxyzABCDEFGHJKLMNPQRSTWXYZ23456789"
        self.assertTrue(heuristics.is_counted_out(value))
        self.assertFalse(heuristics.looks_generated(value))

    def test_the_obvious_runs(self):
        for value in ("abcdefghij", "0123456789abc", "xyzABCDEFGHI"):
            with self.subTest(value=value):
                self.assertTrue(heuristics.is_counted_out(value))

    def test_a_short_run_is_a_coincidence(self):
        # Seven is still a coincidence a generated value can have. Eight is
        # the line, and it is one chance in billions.
        self.assertFalse(heuristics.is_counted_out("Xkabcdefg92Lz4T"))
        self.assertTrue(heuristics.is_counted_out("Xkabcdefgh92Lz4T"))

    def test_a_generated_value_still_looks_generated(self):
        self.assertTrue(heuristics.looks_generated("Xk92mQp7Lz4TvB8nRw1Y"))


class TestAlphabetName(unittest.TestCase):
    """The name and the size have to come from one decision."""

    def test_every_class_is_named_by_the_size_it_counts(self):
        for value in ("1234", "deadbeef", "DEADBEEF", "a-z_1", "A-Z_1",
                      "aZ1", "aZ1+/=", "aZ1 !"):
            with self.subTest(value=value):
                size = heuristics.alphabet_size(value)
                name = heuristics.alphabet_name(value)
                # Every named class maps to exactly one size, so a value
                # landing in a class whose size is not its own means the two
                # lists have drifted apart.
                sizes = {
                    entry[1] for entry in heuristics._ALPHABET_NAMES if entry[2] == name
                }
                self.assertEqual(sizes or {90}, {size}, f"{value!r}: {size} called {name}")

    def test_anything_wider_is_described_rather_than_named(self):
        self.assertEqual(heuristics.alphabet_name("aZ1 !"), "mixed, including punctuation")


if __name__ == "__main__":
    unittest.main()
