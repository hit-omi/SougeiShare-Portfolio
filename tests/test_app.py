"""一時DBで要件と操作の保護を検証します。旧DBは使用しません。"""
import concurrent.futures
import os
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from app import create_app, today_in_japan
from database import get_db

class AppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({'TESTING': True, 'SECRET_KEY': 'test-secret',
                               'DATABASE': self.temp.name+'/test.db'})
        self.a = self.app.test_client()
        self.b = self.app.test_client()
        self.c = self.app.test_client()
    def tearDown(self):
        self.temp.cleanup()
    def post(self, client, url, data, follow=False):
        client.get('/login')
        with client.session_transaction() as s:
            token = s['csrf_token']
        return client.post(url, data={**data,'csrf_token':token}, follow_redirects=follow)
    def create(self, client, uid, name='田中さん'):
        return self.post(client,'/groups/create',{'group_name':'送迎グループ','name':name,
            'user_id':uid,'password':'testpass123'})
    def query(self, sql, params=()):
        with self.app.app_context(): return [dict(x) for x in get_db().execute(sql,params).fetchall()]
    def prepare(self):
        self.assertEqual(self.create(self.a,'userA').status_code,302)
        code=self.query('SELECT code FROM groups')[0]['code']
        self.assertEqual(self.post(self.b,'/groups/join',{'group_code':' '+code+' ',
            'name':'佐藤','user_id':'userB','password':'testpass123'}).status_code,302)
        self.assertEqual(self.create(self.c,'userC','他グループ').status_code,302)
        self.assertEqual(self.post(self.a,'/matches/register',{'match_date':'2020-01-01',
            'venue':'会場A','distance_km':'10'}).status_code,302)
        return self.query('SELECT id FROM matches')[0]['id']
    def update(self,client,mid,direction='going',action='assign',version=0):
        return self.post(client,'/matches/update',{'match_id':mid,'direction':direction,
            'action':action,'version':version})
    def test_empty_and_login(self):
        self.assertEqual(len(self.query('SELECT * FROM users')),0)
        self.assertEqual(len(self.query('SELECT * FROM matches')),0)
        self.assertEqual(self.a.get('/matches').status_code,302)
        self.create(self.a,'UserOne')
        user=self.query('SELECT * FROM users')[0]
        self.assertNotIn('testpass123',user['password_hash'])
        self.post(self.a,'/logout',{})
        for uid,pw in [('UserOne','wrongpass'),('userone','testpass123')]:
            r=self.post(self.a,'/login',{'user_id':uid,'password':pw})
            self.assertIn('ユーザーIDまたは'.encode(),r.data)
        self.assertEqual(self.post(self.a,'/login',{'user_id':'UserOne','password':'testpass123'}).status_code,302)
        self.assertEqual(self.a.get('/logout').status_code,405)
        r=self.post(self.a,'/logout',{},True)
        self.assertIn('ログアウトしました'.encode(),r.data)
    def test_leading_zero_duplicate_atomic(self):
        with patch('app.secrets.randbelow',return_value=1234): self.create(self.a,'sameUser')
        self.assertEqual(self.query('SELECT code FROM groups')[0]['code'],'001234')
        r=self.create(self.b,'sameUser')
        self.assertIn('使用されています'.encode(),r.data)
        self.assertEqual(len(self.query('SELECT * FROM groups')),1)
        self.assertEqual(len(self.query('SELECT * FROM users')),1)
    def test_flow_history_and_group_isolation(self):
        mid=self.prepare()
        self.assertNotIn('会場A'.encode(),self.c.get('/matches').data)
        self.assertNotIn('田中さん'.encode(),self.c.get('/history').data)
        self.assertEqual(self.update(self.c,mid).status_code,404)
        self.assertEqual(self.post(self.c,'/matches/delete',{'match_id':mid}).status_code,404)
        self.update(self.a,mid)
        self.update(self.a,mid,'returning')
        h=self.a.get('/history').data.decode()
        self.assertIn('<td>2</td><td>20.0</td>',h)
        self.assertIn('佐藤',h)
        self.assertNotIn('田中さんさん',h)
        self.update(self.b,mid,action='cancel',version=1)
        h=self.a.get('/history').data.decode()
        self.assertIn('<td>1</td><td>10.0</td>',h)
        self.update(self.b,mid,action='outside',version=2)
        h=self.a.get('/history').data.decode()
        self.assertIn('<td>1</td><td>10.0</td>',h)
        self.update(self.a,mid,action='cancel',version=3)
        self.assertEqual(self.query('SELECT going_status FROM matches')[0]['going_status'],'PENDING')
        self.post(self.b,'/matches/delete',{'match_id':mid})
        h=self.a.get('/history').data.decode()
        self.assertIn('<td>0</td><td>0.0</td>',h)
    def test_stale_and_independent_directions(self):
        mid=self.prepare()
        self.update(self.a,mid)
        self.update(self.b,mid)
        self.assertEqual(self.query('SELECT going_user_id FROM matches')[0]['going_user_id'],1)
        self.update(self.b,mid,'returning')
        self.assertEqual(self.query('SELECT returning_status FROM matches')[0]['returning_status'],'ASSIGNED')
        self.update(self.a,mid,action='cancel',version=1)
        self.update(self.b,mid,version=2)
        self.update(self.a,mid,action='cancel',version=1)
        self.assertEqual(self.query('SELECT going_user_id FROM matches')[0]['going_user_id'],2)
    def test_concurrent_assignment(self):
        mid=self.prepare()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            list(ex.map(lambda c:self.update(c,mid),[self.a,self.b]))
        row=self.query('SELECT going_user_id,going_version FROM matches')[0]
        self.assertIn(row['going_user_id'],[1,2]);self.assertEqual(row['going_version'],1)
    def test_input_and_duplicate_matches(self):
        self.create(self.a,'userA')
        base={'match_date':'2020-01-01','venue':'会場','distance_km':'0'}
        for bad in ['-1','1000','1.23','NaN','inf','1e2','１２']:
            self.assertEqual(self.post(self.a,'/matches/register',{**base,'distance_km':bad}).status_code,200)
        self.assertEqual(len(self.query('SELECT * FROM matches')),0)
        for change in [{'venue':'x'*51},{'match_date':'2026-02-30'}]:
            self.post(self.a,'/matches/register',{**base,**change})
        self.assertEqual(len(self.query('SELECT * FROM matches')),0)
        for dist in ['0','999.9','10.5','10.5']:
            self.assertEqual(self.post(self.a,'/matches/register',{**base,'distance_km':dist}).status_code,302)
        self.assertEqual(len(self.query('SELECT * FROM matches')),4)
        self.assertEqual(self.update(self.a,10**50).status_code,400)
    def test_csrf_all_posts(self):
        self.prepare()
        for route in ['/login','/groups/create','/groups/join','/logout','/matches/register',
                      '/matches/update','/matches/delete','/account/withdraw','/groups/delete']:
            for token in [None,'0'*64,'あ'*64]:
                data={} if token is None else {'csrf_token':token}
                self.assertEqual(self.a.post(route,data=data).status_code,400)
    def test_db_constraints(self):
        mid=self.prepare()
        with self.app.app_context():
            db=get_db()
            for sql,args in [
                ('UPDATE matches SET going_status=\'ASSIGNED\' WHERE id=?',(mid,)),
                ('UPDATE matches SET going_status=\'ASSIGNED\',going_user_id=3 WHERE id=?',(mid,)),
                ('UPDATE matches SET going_status=\'UNKNOWN\' WHERE id=?',(mid,))]:
                with self.assertRaises(sqlite3.IntegrityError):db.execute(sql,args)
                db.rollback()
    def test_xss_escape_and_throttle(self):
        self.create(self.a,'userA','<script>bad</script>')
        r=self.a.get('/matches')
        self.assertNotIn(b'<script>bad</script>',r.data)
        self.assertIn(b'&lt;script&gt;',r.data)
        self.post(self.a,'/logout',{})
        for _ in range(20):self.post(self.b,'/login',{'user_id':'bad','password':'wrongpass'})
        self.assertEqual(self.post(self.b,'/login',{'user_id':'bad','password':'wrongpass'}).status_code,429)
        self.assertEqual(self.b.get('/login').headers['X-Frame-Options'],'DENY')
    def test_persistence(self):
        self.create(self.a,'userA')
        another=create_app({'TESTING':True,'SECRET_KEY':'test-secret','DATABASE':self.temp.name+'/test.db'})
        with another.app_context(): self.assertEqual(get_db().execute('SELECT count(*) FROM users').fetchone()[0],1)
    def test_production_settings(self):
        with patch.dict(os.environ, {'SOUGEISHARE_PRODUCTION':'1'}, clear=True):
            with self.assertRaises(RuntimeError):
                create_app({'DATABASE':self.temp.name+'/public.db'})
        with patch.dict(os.environ, {'SOUGEISHARE_PRODUCTION':'1',
                                    'SOUGEISHARE_SECRET_KEY':'x'*64}, clear=True):
            app=create_app({'TESTING':True,'DATABASE':self.temp.name+'/public.db'})
            c=app.test_client()
            r=c.get('/login',base_url='https://example.test')
            self.assertIn('Secure',r.headers['Set-Cookie'])
            self.assertIn('HttpOnly',r.headers['Set-Cookie'])
            self.assertFalse(app.debug)
    def test_account_validation_and_form_tokens(self):
        data={'group_name':'a','name':'a','user_id':'abc','password':'testpass123'}
        for change in [{'group_name':'a'*31},{'name':'a'*21},{'user_id':'ab'},
                       {'user_id':'abc!'}, {'password':'1234567'},{'password':'a'*129}]:
            self.assertEqual(self.post(self.a,'/groups/create',{**data,**change}).status_code,200)
        self.assertEqual(len(self.query('SELECT * FROM groups')),0)
        self.create(self.a,'userA')
        for route in ['/matches','/matches/register','/history']:
            r=self.a.get(route)
            self.assertEqual(r.status_code,200)
            forms=re.findall(r'<form\b.*?</form>',r.data.decode(),re.S)
            self.assertTrue(forms)
            for form in forms:
                self.assertIn('method="post"',form)
                self.assertIn('name="csrf_token"',form)
    def test_withdraw_preserves_past_and_clears_today_future(self):
        mid=self.prepare()
        for day in ['2026-10-10','2026-10-11']:
            self.post(self.a,'/matches/register',{'match_date':day,'venue':'会場','distance_km':'10'})
        for row in self.query('SELECT id FROM matches'):
            self.update(self.a,row['id'])
            self.update(self.a,row['id'],'returning')
        # 同じユーザーが別ブラウザでログインしている状態も用意します。
        other=self.app.test_client()
        self.post(other,'/login',{'user_id':'userA','password':'testpass123'})
        self.assertEqual(self.post(self.a,'/account/withdraw',{'password':'badpass','confirmed':'yes'}).status_code,200)
        self.assertEqual(self.query('SELECT is_active FROM users WHERE id=1')[0]['is_active'],1)
        with patch('app.today_in_japan',return_value='2026-10-10'):
            r=self.post(self.a,'/account/withdraw',{'password':'testpass123','confirmed':'yes'})
        self.assertEqual(r.status_code,302)
        self.assertEqual(self.query('SELECT is_active FROM users WHERE id=1')[0]['is_active'],0)
        rows=self.query('SELECT * FROM matches ORDER BY id')
        self.assertEqual(rows[0]['going_status'],'ASSIGNED')
        for row in rows[1:]:
            self.assertEqual(row['going_status'],'PENDING')
            self.assertEqual(row['returning_status'],'PENDING')
            self.assertEqual(row['going_version'],2)
        h=self.b.get('/history').data.decode()
        self.assertIn('退会済み',h);self.assertIn('<td>2</td><td>20.0</td>',h)
        self.assertEqual(other.get('/matches').status_code,302)
        r=self.post(self.a,'/login',{'user_id':'userA','password':'testpass123'})
        self.assertIn('ユーザーIDまたは'.encode(),r.data)
        self.assertEqual(self.query('SELECT COUNT(*) AS n FROM groups')[0]['n'],2)
    def test_group_delete_any_member_isolated_and_invalidates_sessions(self):
        self.prepare()
        group=self.query('SELECT * FROM groups WHERE id=1')[0]
        base={'password':'testpass123','group_code':group['code'],'confirmed':'yes'}
        for change in [{'password':'badpass'},{'group_code':'abcdef'},{'confirmed':''}]:
            r=self.post(self.b,'/groups/delete',{**base,**change})
            self.assertEqual(r.status_code,200)
            self.assertEqual(len(self.query('SELECT * FROM groups')),2)
        # 他グループのコードを入れても、削除できません。
        wrong=self.query('SELECT code FROM groups WHERE id=2')[0]['code']
        self.assertEqual(self.post(self.b,'/groups/delete',{**base,'group_code':wrong}).status_code,200)
        # 作成者以外のメンバーが削除します。フォームの偽group_idは無視します。
        self.assertEqual(self.post(self.b,'/groups/delete',{**base,'group_id':'2'}).status_code,302)
        self.assertEqual(len(self.query('SELECT * FROM matches')),0)
        self.assertEqual([u['user_id'] for u in self.query('SELECT * FROM users')],['userC'])
        self.assertEqual([g['id'] for g in self.query('SELECT * FROM groups')],[2])
        self.assertEqual(self.a.get('/history').status_code,302)
        self.assertEqual(self.c.get('/matches').status_code,200)
    def test_missing_confirmation_and_last_member(self):
        self.create(self.a,'userA')
        self.assertIn('あなた1人'.encode(),self.a.get('/account/withdraw').data)
        self.post(self.a,'/account/withdraw',{'password':'testpass123'})
        self.assertEqual(self.query('SELECT is_active FROM users')[0]['is_active'],1)
        self.assertEqual(self.a.get('/groups/delete').status_code,200)
    def test_existing_db_migration(self):
        path=self.temp.name+'/old.db'
        with sqlite3.connect(path) as db:
            # この機能追加前のv2のusers定義を再現します。
            db.executescript('''
                CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, code TEXT UNIQUE);
                CREATE TABLE users (id INTEGER PRIMARY KEY, user_id TEXT UNIQUE, name TEXT,
                    password_hash TEXT, group_id INTEGER, UNIQUE(id,group_id));
                INSERT INTO groups VALUES (1,'旧グループ','001234');
                INSERT INTO users VALUES (1,'oldUser','既存メンバー','unused',1);
            ''')
        migrated=create_app({'TESTING':True,'SECRET_KEY':'test-secret','DATABASE':path})
        for _ in range(2):
            with migrated.app_context():
                from database import init_db
                init_db()
                row=get_db().execute('SELECT * FROM users').fetchone()
                self.assertEqual(row['user_id'],'oldUser');self.assertEqual(row['is_active'],1)
                self.assertEqual(get_db().execute('SELECT code FROM groups').fetchone()[0],'001234')
    def test_japan_date_and_changed_ui_text(self):
        from datetime import datetime, timezone, timedelta
        self.assertEqual(today_in_japan(),datetime.now(timezone(timedelta(hours=9))).date().isoformat())
        h=self.a.get('/groups/join').data.decode()
        for text in ['半角の数字6桁','1～20文字','半角英数字・_・-で3～30文字（大文字と小文字は区別）','8文字以上']:
            self.assertIn(text,h)
    def test_group_deletion_includes_withdrawn_members(self):
        self.prepare()
        self.update(self.a,1)
        code=self.query('SELECT code FROM groups WHERE id=1')[0]['code']
        self.post(self.a,'/account/withdraw',{'password':'testpass123','confirmed':'yes'})
        self.assertEqual(self.query('SELECT is_active FROM users WHERE id=1')[0]['is_active'],0)
        self.assertEqual(self.post(self.b,'/groups/delete',{'password':'testpass123',
                         'group_code':code,'confirmed':'yes'}).status_code,302)
        self.assertEqual(len(self.query('SELECT * FROM users WHERE group_id=1')),0)
        self.assertEqual(len(self.query('SELECT * FROM matches WHERE group_id=1')),0)
        self.assertEqual(self.c.get('/matches').status_code,200)

if __name__=='__main__':unittest.main(verbosity=2)
