import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class BaselineUpdateContinuousTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.temp_dir.name)
        self.zeek_dir = self.workdir / "zeek-logs" / "merged-20260306T080000-20260306T083000.pcap.zeek"
        self.zeek_dir.mkdir(parents=True)
        self.db_path = self.workdir / "state" / "baselines.sqlite"
        self.db_path.parent.mkdir(parents=True)
        self.eve_path = self.workdir / "suricata" / "eve-merged-20260306T080000-20260306T083000.json"
        self.eve_path.parent.mkdir(parents=True)

        (self.zeek_dir / "conn.log").write_text(
            textwrap.dedent(
                """\
                #separator \\x09
                #fields ts id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes
                1709712000.0\t192.168.1.50\t93.184.216.34\t443\ttcp\t120\t240
                """
            ),
            encoding="utf-8",
        )
        (self.zeek_dir / "dns.log").write_text(
            textwrap.dedent(
                """\
                #separator \\x09
                #fields ts id.orig_h query rcode_name
                1709712000.0\t192.168.1.50\texample.com\tNOERROR
                """
            ),
            encoding="utf-8",
        )
        self.eve_path.write_text(
            '{"event_type":"tls","timestamp":"2026-03-06T08:10:00Z","src_ip":"192.168.1.50","dest_ip":"93.184.216.34","tls":{"ja3":"abc123"}}\n',
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_updates_are_idempotent_per_source_key(self):
        script = REPO_ROOT / "scripts" / "baseline_update_continuous.py"
        args = [
            sys.executable,
            str(script),
            "--zeek-dir",
            str(self.zeek_dir),
            "--db",
            str(self.db_path),
            "--eve",
            str(self.eve_path),
            "--source-key",
            "fixture-1",
        ]

        subprocess.run(args, check=True)
        subprocess.run(args, check=True)

        conn = sqlite3.connect(self.db_path)
        dest_count = conn.execute("SELECT count FROM dest_counts_rolling").fetchone()[0]
        dns_count = conn.execute("SELECT count FROM dns_counts_rolling").fetchone()[0]
        tls_count = conn.execute("SELECT count FROM tls_fp_rolling").fetchone()[0]
        processed = conn.execute("SELECT COUNT(*) FROM processed_artifacts WHERE source_key = 'fixture-1'").fetchone()[0]
        conn.close()

        self.assertEqual(dest_count, 1)
        self.assertEqual(dns_count, 1)
        self.assertEqual(tls_count, 1)
        self.assertEqual(processed, 1)


if __name__ == "__main__":
    unittest.main()
