"""验证发布脚本只使用显式部署参数，测试不会访问真实管理 API。"""
import contextlib
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('cloudflare-kex.py')


class DeploymentConfigTests(unittest.TestCase):
    def execute(self, action, *, extra=(), state=None):
        calls = []

        class Response:
            ok = True
            status_code = 200

            def __init__(self, result):
                self.result = result

            def json(self):
                return {'success': True, 'result': self.result}

        class Session:
            def __init__(self):
                self.headers = {}
                self.proxies = {}

            def request(self, method, url, **kwargs):
                calls.append((method, url, kwargs))
                if url.endswith('/zones'):
                    return Response([{'id': 'test-zone'}])
                if url.endswith('/dns_records') and method == 'GET':
                    return Response([])
                if url.endswith('/dns_records') and method == 'POST':
                    return Response({'id': 'test-record'})
                raise AssertionError('意外的管理请求：' + method + ' ' + url)

        # 配置、令牌与状态只写入临时目录，不依赖开发者环境。
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            (private / 'credentials.json').write_text(json.dumps({
                'apiToken': 'test-token-not-a-secret', 'accountId': 'test-account'
            }), encoding='utf-8')
            if state is not None:
                (private / 'kex-state.json').write_text(json.dumps(state), encoding='utf-8')
            argv = [str(SCRIPT), action, '--secrets', directory,
                    '--zone', 'example.com', '--origin', 'origin.example.com',
                    '--worker-host', 'entry.example.com', '--server-ip', '192.0.2.40', *extra]
            with patch.object(sys, 'argv', argv), patch('requests.Session', Session), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                runpy.run_path(str(SCRIPT), run_name='__main__')
            return calls, json.loads((private / 'kex-state.json').read_text(encoding='utf-8'))

    def test_dns_uses_explicit_zone_origin_and_address(self):
        calls, state = self.execute('dns')
        self.assertEqual(calls[0][2]['params'], {'name': 'example.com'})
        write = next(call for call in calls if call[0] == 'POST')
        self.assertEqual(write[2]['json']['name'], 'origin.example.com')
        self.assertEqual(write[2]['json']['content'], '192.0.2.40')
        self.assertEqual(state['workerHost'], 'entry.example.com')

    def test_prepare_only_reads_zone_and_saves_selected_targets(self):
        calls, state = self.execute('prepare')
        self.assertEqual([call[0] for call in calls], ['GET'])
        self.assertEqual(state['origin'], 'origin.example.com')
        self.assertEqual(state['workerHost'], 'entry.example.com')
        self.assertTrue(state['clientToken'])

    def test_domain_outside_zone_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.execute('dns', extra=['--origin', 'origin.invalid'])

    def test_same_worker_and_origin_are_rejected(self):
        with self.assertRaises(SystemExit):
            self.execute('dns', extra=['--worker-host', 'origin.example.com'])

    def test_old_state_cannot_redirect_new_deployment(self):
        with self.assertRaises(SystemExit):
            self.execute('dns', state={'origin': 'other.example.com'})


if __name__ == '__main__':
    unittest.main()
