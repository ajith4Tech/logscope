"""Log templates: stable across variable parts, distinct across events."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.patterns import (  # noqa: E402
    count_bucket,
    digest_records,
    namespace_pattern,
    normalize_message,
    pod_pattern,
    template_id,
)

# Each case: two lines of the same event that differ only in variable parts.
LINES = [
    ('2026-09-07 12:00:01.123 UTC [4231] FATAL:  password authentication failed for user "app1"',
     '2026-09-08 07:13:44.902 UTC [77] FATAL:  password authentication failed for user "app22"'),
    ('2026-09-07 12:00:01.123 UTC [77] ERROR:  duplicate key value violates unique constraint "users_pkey"',
     '2026-09-07 13:10:09.001 UTC [91] ERROR:  duplicate key value violates unique constraint "users_pkey"'),
    ('2026-09-07 12:00:02 UTC [12] FATAL:  sorry, too many clients already',
     '2026-09-09 01:02:03 UTC [4410] FATAL:  sorry, too many clients already'),
    ('2026-09-07 12:00:03.5 UTC [88] ERROR:  deadlock detected',
     '2026-09-07 12:30:59.25 UTC [123] ERROR:  deadlock detected'),
    ('ERROR:  relation "orders" does not exist at character 15',
     'ERROR:  relation "orders" does not exist at character 152'),
    ('E0907 12:00:00.123456       1 reflector.go:138] failed to list *v1.Pod: Get "https://10.43.0.1:443/api/v1/pods?limit=500": dial tcp 10.43.0.1:443: i/o timeout',
     'E0908 03:11:52.000001       1 reflector.go:138] failed to list *v1.Pod: Get "https://10.43.0.9:443/api/v1/pods?limit=500": dial tcp 10.43.0.9:443: i/o timeout'),
    ('Back-off restarting failed container app in pod web-7d9f8b6c5d-x2kqp_default(3f2b9c1e-1111-2222-3333-444455556666)',
     'Back-off restarting failed container app in pod web-5c4b8d7f9-m2n8q_default(aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)'),
    ('Readiness probe failed: Get "http://10.42.0.15:8080/healthz": context deadline exceeded',
     'Readiness probe failed: Get "http://10.42.3.201:8080/healthz": context deadline exceeded'),
    ('Liveness probe failed: HTTP probe failed with statuscode: 500',
     'Liveness probe failed: HTTP probe failed with statuscode: 503'),
    ('Failed to pull image "registry.example.com/shop/api:1.4.2": rpc error: code = NotFound',
     'Failed to pull image "registry.example.com/shop/api:1.5.0": rpc error: code = NotFound'),
    ('panic: runtime error: index out of range [5] with length 3',
     'panic: runtime error: index out of range [12] with length 10'),
    ('goroutine 42 [running]:', 'goroutine 7 [running]:'),
    ('Traceback (most recent call last):\n  File "/app/worker.py", line 12, in <module>\nKeyError: \'user_id\'',
     'Traceback (most recent call last):\n  File "/app/worker.py", line 98, in <module>\nKeyError: \'user_id\''),
    ('Exception in thread "main" java.lang.OutOfMemoryError: Java heap space',
     'Exception in thread "main" java.lang.OutOfMemoryError: Java heap space'),
    ('12:00:00.111111111: Critical Terminal shell in container (user=root container=nginx proc=sh)',
     '18:42:13.000000001: Critical Terminal shell in container (user=root container=nginx proc=sh)'),
    ('Notice Sensitive file opened for reading (file=/etc/shadow user=www-data)',
     'Notice Sensitive file opened for reading (file=/etc/shadow user=www-data)'),
    ('Unexpected outbound connection destination (command=curl 203.0.113.9 connection=10.42.0.7:51234->203.0.113.9:443)',
     'Unexpected outbound connection destination (command=curl 198.51.100.4 connection=10.42.1.9:40000->198.51.100.4:443)'),
    ('request completed in 250ms status=200 path=/api/v1/orders/12345 from 192.168.1.20:5432',
     'request completed in 1.5s status=201 path=/api/v1/orders/987 from 192.168.7.3:61000'),
    ('container 3f9a2b7c1d4e exited with code 137 (OOMKilled)',
     'container 0a1b2c3d4e5f exited with code 137 (OOMKilled)'),
    ('write /var/lib/postgresql/data/base/16384/2619: No space left on device',
     'write /var/lib/postgresql/data/base/16385/1259: No space left on device'),
]


def test_twenty_lines_are_stable_and_never_over_merged():
    assert len(LINES) == 20
    templates = []
    for first, second in LINES:
        a, b = normalize_message(first), normalize_message(second)
        assert a == b, (first, a, b)
        assert normalize_message(a) == a  # idempotent
        templates.append(a)
    # Twenty different events: twenty different templates.
    assert len(set(templates)) == 20, [t for t in templates if templates.count(t) > 1]


def test_placeholders():
    assert normalize_message("connect to [2001:db8::1]:443 at 2026-09-07T10:00:00Z failed after 3m20s") == \
        "connect to [<IP>]:<NUM> at <TS> failed after <DUR>"
    assert normalize_message("id 6f1c2d3e-0a1b-4c5d-8e9f-001122334455 hash deadbeef42") == "id <UUID> hash <HEX>"
    assert normalize_message('{"msg":"payment failed","order":"A-1001"}') == '{"msg":"payment failed","order":"<STR>"}'
    assert normalize_message("open /proc/4242/status") == "open <PATH>"
    assert normalize_message("open /etc/hosts") == "open /etc/hosts"  # no digits: kept


def test_namespace_and_pod_patterns():
    assert namespace_pattern("user-123") == "user-*" == namespace_pattern("user-9")
    assert namespace_pattern("tenant-7-prod") == "tenant-*-prod"
    assert namespace_pattern("kube-system") == "kube-system"
    assert pod_pattern("web-7d9f8b6c5d-x2kqp") == pod_pattern("web-5c4b8d7f9-m2n8q") == "web-<HASH>"
    template = normalize_message("ready")
    assert template_id("user-1", "app", template) == template_id("user-42", "app", template)
    assert template_id("user-1", "app", template) != template_id("user-1", "sidecar", template)
    assert template_id("shop", "app", template) != template_id("billing", "app", template)


@pytest.mark.parametrize("count,bucket", [(1, 1), (2, 2), (3, 2), (4, 4), (7, 4), (8, 8), (1000, 512)])
def test_count_bucket(count, bucket):
    assert count_bucket(count) == bucket


def test_digest_keeps_top_templates_with_counts_times_and_redacted_exemplars():
    rows = [{"message": f"login failed for token=sk-abcdefghijklmnopqrstu{i} from 10.0.0.{i}",
             "timestamp": f"2026-09-07T10:0{i}:00Z", "namespace": "shop", "container": "app", "pod": f"web-{i}"}
            for i in range(5)]
    rows.append({"message": "cache warmed", "timestamp": "2026-09-07T09:00:00Z", "namespace": "shop"})
    digest = digest_records(rows, redact=lambda t: t.replace("sk-", "[REDACTED]"))
    top = digest["templates"][0]
    assert digest["rows"] == 6 and digest["distinct_templates"] == 2
    assert top["count"] == 5 and top["pods"] == 5
    assert (top["first_seen"], top["last_seen"]) == ("2026-09-07T10:00:00Z", "2026-09-07T10:04:00Z")
    assert len(top["exemplars"]) == 3 and all("sk-" not in e for e in top["exemplars"])
    assert digest["templates"][1]["exemplars"] == []  # identical to its template
