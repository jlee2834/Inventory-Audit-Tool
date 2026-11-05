import os, tempfile, unittest
os.environ.setdefault('SECRET_KEY','test-secret-for-local-tests-only')
os.environ['COOKIE_SECURE']='false'
from app import app, db
from werkzeug.security import generate_password_hash

class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();app.config.update(TESTING=True,DATABASE=self.tmp.name+'/test.db',SECRET_KEY='test-secret')
        self.client=app.test_client()
        with app.app_context():
            db().executescript('''CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL);''')
            from app import init_db
            init_db()
            db().execute('INSERT INTO teams(name) VALUES(?)',('Alpha',))
            db().execute('INSERT INTO users(username,password_hash,role,team_id) VALUES(?,?,?,?)',('counter',generate_password_hash('test-password-long'),'counter',1))
            db().execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',('admin',generate_password_hash('test-password-long'),'admin'))
            db().commit()
    def tearDown(self): self.tmp.cleanup()
    def login(self,username):
        self.client.get('/login')
        with self.client.session_transaction() as sess: token=sess['csrf']
        return self.client.post('/login',data={'username':username,'password':'test-password-long','csrf':token})
    def test_employee_cannot_access_admin(self):
        self.login('counter');self.assertEqual(self.client.get('/admin').status_code,403)
    def test_leaderboard_available_to_employee_and_admin(self):
        for username in ('counter','admin'):
            with self.client.session_transaction() as sess: sess.clear()
            self.login(username)
            response=self.client.get('/leaderboard')
            self.assertEqual(response.status_code,200)
            self.assertIn(b'Team leaderboard',response.data)
            self.assertNotIn(b'Expected quantity',response.data)
    def test_csrf_rejects_post(self):
        self.login('admin');self.assertEqual(self.client.post('/admin/teams',data={'name':'Evil'}).status_code,400)
    def test_login(self):
        self.assertEqual(self.login('counter').status_code,302)
        self.assertEqual(self.client.get('/my-counts').status_code,200)
if __name__=='__main__': unittest.main()

class NewFeaturesTests(AuditTests):
    def csrf(self):
        with self.client.session_transaction() as sess: return sess['csrf']
    def test_registration_requires_approval(self):
        app.config['ALLOW_SELF_REGISTRATION']=True
        self.client.get('/register')
        r=self.client.post('/register',data={'username':'newemployee','password':'a-strong-password-123','csrf':self.csrf()})
        self.assertEqual(r.status_code,302)
        with app.app_context():
            u=db().execute('SELECT approved FROM users WHERE username=?',('newemployee',)).fetchone()
            self.assertEqual(u['approved'],0)
        app.config['ALLOW_SELF_REGISTRATION']=False
    def test_individual_count_authorization(self):
        with app.app_context():
            db().execute("INSERT INTO audits(name,status,created_at) VALUES('Test','active','2026-01-01')")
            db().execute("INSERT INTO parts(sku,description) VALUES('ABC','Widget')")
            db().execute('INSERT INTO audit_items(audit_id,part_id,expected_qty) VALUES(1,1,10)')
            db().execute('INSERT INTO individual_assignments(item_id,user_id) VALUES(1,1)')
            db().commit()
        self.login('counter')
        response=self.client.get('/my-counts')
        self.assertIn(b'ABC',response.data)
        self.assertNotIn(b'10</',response.data)
        self.assertEqual(self.client.post('/individual-count/1',data={'csrf':self.csrf(),'quantity':'8'}).status_code,302)
        with app.app_context(): self.assertEqual(db().execute('SELECT quantity FROM individual_counts').fetchone()['quantity'],8)
