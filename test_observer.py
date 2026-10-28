import hashlib
import http.client
import threading
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import observer as o


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.paths = patch.multiple(o, STATE_DIR=root, BLOCK_DIR=root/'blocks', DB_PATH=root/'observer.sqlite3', LOG_PATH=root/'observer.log')
        self.paths.start()
        self.addCleanup(self.paths.stop)
        o.init_db()

    def chain(self, coin_height, spend_height, timestamp=None, offset='a'):
        timestamp = o.RDTS_EXPIRY-1000 if timestamp is None else timestamp
        def name(height):
            return hashlib.sha256(f'{offset}-{height}'.encode()).hexdigest()
        with o.db() as connection:
            connection.executemany('INSERT INTO blocks(hash,prev_hash,height,timestamp,received_at,legacy_maturity_ok,long_maturity_ok) VALUES(?,?,?,?,0,1,1)',
                ((name(h),name(h-1),h,timestamp) for h in range(coin_height-11, spend_height)))
            connection.execute('INSERT INTO coinbases(txid,height,block_hash) VALUES(?,?,?)',('reward',coin_height,name(coin_height)))
        return name(spend_height-1)

    def test_activation_and_maturity_parameters(self):
        self.assertEqual(o.ACTIVATION_HEIGHT,979919)
        self.assertEqual(o.LONG_MATURITY,25920)
        self.assertEqual(o.RDTS_EXPIRY,1819756800)
        self.assertIsNone(o.RELEASE_HEIGHT)

    def test_new_coinbase_at_100_blocks_disagrees(self):
        parent=self.chain(979919,980019)
        self.assertEqual(o.maturity_labels(980019,['reward'],parent)[:2],(1,0))

    def test_first_reward_exact_25920_boundary(self):
        parent=self.chain(979919,1005839)
        self.assertEqual(o.maturity_labels(1005839,['reward'],parent)[:2],(1,1))
        self.assertEqual(o.maturity_labels(1005838,['reward'],parent)[:2],(1,0))

    def test_pre_activation_reward_does_not_acquire_rolling_lock(self):
        parent=self.chain(979818,979920)
        self.assertEqual(o.maturity_labels(979920,['reward'],parent)[:2],(1,1))

    def test_historical_rule_still_applies_before_release(self):
        parent=self.chain(979818,979919)
        self.assertEqual(o.maturity_labels(979919,['reward'],parent)[:2],(0,0))

    def test_post_expiry_reward_uses_100_blocks(self):
        parent=self.chain(1000000,1000100,o.RDTS_EXPIRY)
        self.assertEqual(o.maturity_labels(1000100,['reward'],parent)[:2],(1,1))

    def test_pre_expiry_reward_stays_locked_after_expiry(self):
        parent=self.chain(1000000,1000100,o.RDTS_EXPIRY-1)
        with o.db() as connection:
            connection.execute('UPDATE blocks SET timestamp=? WHERE height>1000000',(o.RDTS_EXPIRY+1000,))
        self.assertEqual(o.maturity_labels(1000100,['reward'],parent)[:2],(1,0))

    def test_expiry_uses_parent_median_not_mining_block_timestamp(self):
        parent=self.chain(1000000,1000100,o.RDTS_EXPIRY-1)
        with o.db() as connection:
            connection.execute('UPDATE blocks SET timestamp=? WHERE height>=1000000',(o.RDTS_EXPIRY+1000,))
        self.assertEqual(o.maturity_labels(1000100,['reward'],parent)[:2],(1,0))

    def test_sibling_coinbase_is_not_treated_as_ancestor(self):
        self.chain(979919,980019,offset='other')
        parent=self.chain(979919,980019,offset='main')
        # Simulate distinct coinbase IDs on the two branches.
        with o.db() as connection:
            connection.execute("UPDATE coinbases SET txid='main-reward' WHERE block_hash=?",(hashlib.sha256(b'main-979919').hexdigest(),))
        self.assertEqual(o.maturity_labels(980019,['reward'],parent)[:2],(1,1))

    def test_missing_parent_is_pending(self):
        self.chain(979919,980019)
        self.assertEqual(o.maturity_labels(980019,['reward'],'missing')[:2],(None,None))

    def test_unknown_inputs_never_claim_full_validation(self):
        result=o.maturity_labels(980019,['not-in-observation'])
        self.assertIn('partial observation',result[2])

    def test_late_ancestry_rechecks_stored_child(self):
        parent=self.chain(979919,980019)
        child='f'*64
        with o.db() as connection:
            connection.execute('INSERT INTO blocks(hash,prev_hash,height,timestamp,received_at) VALUES(?,?,?,0,0)',(child,parent,980019))
            connection.execute('INSERT INTO block_inputs(block_hash,txid) VALUES(?,?)',(child,'reward'))
        o.recheck_descendants(parent)
        with o.db() as connection:
            row=connection.execute('SELECT legacy_maturity_ok,long_maturity_ok FROM blocks WHERE hash=?',(child,)).fetchone()
        self.assertEqual(tuple(row),(1,0))

    def test_expiry_uses_the_median_of_eleven_parent_timestamps(self):
        parent=self.chain(1000000,1000100,o.RDTS_EXPIRY-1)
        with o.db() as connection:
            # Five new timestamps do not move the median over the cutoff.
            connection.execute('UPDATE blocks SET timestamp=? WHERE height BETWEEN 999995 AND 999999',(o.RDTS_EXPIRY,))
        self.assertEqual(o.maturity_labels(1000100,['reward'],parent)[:2],(1,0))
        with o.db() as connection:
            connection.execute('UPDATE blocks SET timestamp=? WHERE height=999994',(o.RDTS_EXPIRY,))
        self.assertEqual(o.maturity_labels(1000100,['reward'],parent)[:2],(1,1))

    def test_database_connections_are_closed(self):
        with o.db() as connection:
            connection.execute('SELECT 1')
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute('SELECT 1')

    def test_persistent_split_count_does_not_use_graph_window(self):
        with o.db() as connection:
            connection.executemany('INSERT INTO blocks(hash,prev_hash,height,timestamp,received_at) VALUES(?,?,?,0,0)',
                [('a','parent',979919),('b','parent',979919)]+[(f'new-{n}',f'new-{n-1}',980000+n) for n in range(1205)])
        data=o.status_payload()
        self.assertEqual(data['counts']['recorded_splits'],1)
        self.assertEqual(len(data['chain']['blocks']),1200)

    def test_conflict_survives_recent_graph_window(self):
        self.chain(979919,981130)
        with o.db() as connection:
            connection.execute('UPDATE blocks SET long_maturity_ok=0 WHERE height=979919')
            data=o.branch_data(connection)
        hashes={block['hash'] for block in data['blocks']}
        roots=[block for block in data['blocks'] if block['prev_hash'] not in hashes]
        self.assertTrue(roots)
        self.assertTrue(all(block['prefix_long_ok'] is False for block in roots))

    def test_peer_versions_do_not_confuse_previous_release(self):
        self.assertEqual(o.peer_rule_set('/Satoshi:29.4.2/Knots:20260508/'),'legacy')
        self.assertEqual(o.peer_rule_set('/Satoshi:29.4.3/Knots:20260508/'),'new')
        self.assertEqual(o.peer_rule_set('/unrecognised:1/'),'unknown')

    def test_http_archive_never_initializes_live_state_and_cors_is_scoped(self):
        server=o.ThreadingHTTPServer(('127.0.0.1',0),o.DashboardHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            with patch.object(o,'ARCHIVE_MODE',True), patch.object(o,'db',side_effect=AssertionError('Archive touched live DB')):
                connection=http.client.HTTPConnection('127.0.0.1',server.server_port)
                connection.request('GET','/api/status',headers={'Origin':'https://lukecoin.zndtoshi.com'})
                response=connection.getresponse()
                self.assertEqual(response.getheader('Access-Control-Allow-Origin'),'https://lukecoin.zndtoshi.com')
                self.assertEqual(json.loads(response.read())['observer']['mode'],'historical-snapshot')
                connection.request('GET','/api/status',headers={'Origin':'https://unrelated.example'})
                response=connection.getresponse()
                self.assertIsNone(response.getheader('Access-Control-Allow-Origin'))
                response.read()
                connection.close()
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_frozen_snapshot_unchanged_and_split_count_correct(self):
        raw=(o.STATIC_DIR/'snapshot.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'7e6dfdd091e2b587f6f747ad2f1410c015baa6c11ea6667beffc796aebd08188')
        data=json.loads(raw)
        self.assertEqual(len(data['chain']['forks']),8)
        self.assertEqual(data['counts']['rule_splits'],9)

    def test_failed_request_released_from_queue(self):
        block_hash='a'*64
        o.enqueue_block(block_hash,979919,'test')
        worker=o.PeerWorker('8.8.8.8',8333)
        pending=worker.next_request()
        def fail():
            worker.pending_request=pending
            raise ConnectionError('interrupted')
        with patch.object(worker,'_session',side_effect=fail):
            with self.assertRaises(ConnectionError): worker.session()
        self.assertNotIn(block_hash,o.queued_hashes)
        self.assertEqual(o.download_queue.unfinished_tasks,0)


if __name__=='__main__':
    unittest.main()
