import os, csv, io, sqlite3, secrets, hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, g, request, redirect, url_for, render_template, flash, session, abort, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app=Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY',''), DATABASE=os.environ.get('DATABASE','/data/inventory.db'), MAX_CONTENT_LENGTH=5*1024*1024, ALLOW_SELF_REGISTRATION=os.environ.get('ALLOW_SELF_REGISTRATION','false').lower()=='true', SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','true').lower()=='true')
if not app.config['SECRET_KEY']:
    raise RuntimeError('Set SECRET_KEY environment variable')
if os.environ.get('TRUST_PROXY','false').lower()=='true': app.wsgi_app=ProxyFix(app.wsgi_app,x_for=1,x_proto=1,x_host=1)

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def db():
    if 'db' not in g:
        os.makedirs(os.path.dirname(app.config['DATABASE']) or '.',exist_ok=True)
        g.db=sqlite3.connect(app.config['DATABASE'],timeout=20)
        g.db.row_factory=sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
        g.db.execute('PRAGMA busy_timeout=20000')
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db
@app.teardown_appcontext
def close_db(exc):
    conn=g.pop('db',None)
    if conn: conn.close()

def init_db():
    with app.app_context():
        conn=db()
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','counter')),team_id INTEGER REFERENCES teams(id),active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY,name TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','active','closed')),created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS parts(id INTEGER PRIMARY KEY,sku TEXT UNIQUE NOT NULL,description TEXT NOT NULL,location TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS audit_items(id INTEGER PRIMARY KEY,audit_id INTEGER NOT NULL REFERENCES audits(id),part_id INTEGER NOT NULL REFERENCES parts(id),expected_qty INTEGER NOT NULL CHECK(expected_qty>=0),description_snapshot TEXT,location_snapshot TEXT,UNIQUE(audit_id,part_id));
        CREATE TABLE IF NOT EXISTS assignments(id INTEGER PRIMARY KEY,item_id INTEGER NOT NULL REFERENCES audit_items(id),team_id INTEGER NOT NULL REFERENCES teams(id),UNIQUE(item_id,team_id));
        CREATE TABLE IF NOT EXISTS counts(id INTEGER PRIMARY KEY,assignment_id INTEGER NOT NULL REFERENCES assignments(id),user_id INTEGER NOT NULL REFERENCES users(id),quantity INTEGER NOT NULL CHECK(quantity>=0),round INTEGER NOT NULL DEFAULT 1 CHECK(round>=1),submitted_at TEXT NOT NULL,UNIQUE(assignment_id,round));
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,actor_id INTEGER REFERENCES users(id),action TEXT NOT NULL,details TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS recount_requests(assignment_id INTEGER PRIMARY KEY REFERENCES assignments(id),round INTEGER NOT NULL,requested_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS registration_tokens(id INTEGER PRIMARY KEY,token_hash TEXT UNIQUE NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('invite','reset')),user_id INTEGER REFERENCES users(id),created_by INTEGER REFERENCES users(id),expires_at TEXT NOT NULL,used_at TEXT);
        CREATE TABLE IF NOT EXISTS individual_assignments(id INTEGER PRIMARY KEY,item_id INTEGER NOT NULL REFERENCES audit_items(id),user_id INTEGER NOT NULL REFERENCES users(id),UNIQUE(item_id,user_id));
        CREATE TABLE IF NOT EXISTS individual_counts(id INTEGER PRIMARY KEY,assignment_id INTEGER NOT NULL REFERENCES individual_assignments(id),user_id INTEGER NOT NULL REFERENCES users(id),quantity INTEGER NOT NULL CHECK(quantity>=0),submitted_at TEXT NOT NULL,UNIQUE(assignment_id));
        CREATE TABLE IF NOT EXISTS login_attempts(username TEXT PRIMARY KEY,failures INTEGER NOT NULL DEFAULT 0,locked_until TEXT);
        CREATE INDEX IF NOT EXISTS idx_assignments_team ON assignments(team_id);
        CREATE INDEX IF NOT EXISTS idx_items_audit ON audit_items(audit_id);
        CREATE INDEX IF NOT EXISTS idx_counts_assignment ON counts(assignment_id);
        ''')
        if 'approved' not in [r['name'] for r in conn.execute('PRAGMA table_info(users)')]:
            conn.execute('ALTER TABLE users ADD COLUMN approved INTEGER NOT NULL DEFAULT 1')
        for column in ('description_snapshot','location_snapshot'):
            if column not in [r['name'] for r in conn.execute('PRAGMA table_info(audit_items)')]:
                conn.execute(f'ALTER TABLE audit_items ADD COLUMN {column} TEXT')
        conn.execute('''UPDATE audit_items SET description_snapshot=COALESCE(description_snapshot,(SELECT description FROM parts WHERE parts.id=audit_items.part_id)),location_snapshot=COALESCE(location_snapshot,(SELECT location FROM parts WHERE parts.id=audit_items.part_id)) WHERE description_snapshot IS NULL OR location_snapshot IS NULL''')
        conn.commit()

def event(action,details): db().execute('INSERT INTO events(actor_id,action,details,created_at) VALUES(?,?,?,?)',(session.get('uid'),action,str(details)[:1000],now()))
@app.before_request
def security():
    if 'csrf' not in session: session['csrf']=secrets.token_hex(32)
    if request.method=='POST':
        if not session.get('csrf') or not secrets.compare_digest(session['csrf'],request.form.get('csrf','')): abort(400,'Invalid CSRF token')
    g.user=db().execute('SELECT * FROM users WHERE id=? AND active=1 AND approved=1',(session.get('uid',-1),)).fetchone()
@app.context_processor
def context(): return {'csrf':session.get('csrf',''),'user':getattr(g,'user',None)}
def login_required(fn):
    @wraps(fn)
    def inner(*args,**kwargs):
        if not g.user: return redirect(url_for('login'))
        return fn(*args,**kwargs)
    return inner
def admin_required(fn):
    @wraps(fn)
    @login_required
    def inner(*args,**kwargs):
        if g.user['role']!='admin': abort(403)
        return fn(*args,**kwargs)
    return inner

def integer(value):
    try:
        if not str(value).isdigit(): raise ValueError()
        v=int(value)
        if v>2147483647: raise ValueError()
        return v
    except (ValueError,TypeError): abort(400,'Expected a non-negative integer')

@app.route('/health')
def health(): return {'status':'ok'}
@app.route('/')
def index(): return redirect(url_for('admin_dashboard' if g.user and g.user['role']=='admin' else 'my_counts'))
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username','').strip()[:128]
        attempt=db().execute('SELECT * FROM login_attempts WHERE username=?',(username,)).fetchone()
        if attempt and attempt['locked_until'] and attempt['locked_until']>now(): abort(429,'Too many login attempts. Try again later.')
        u=db().execute('SELECT * FROM users WHERE username=? AND active=1 AND approved=1',(username,)).fetchone()
        if u and check_password_hash(u['password_hash'],request.form.get('password','')):
            db().execute('DELETE FROM login_attempts WHERE username=?',(username,));db().commit()
            session.clear();session['uid']=u['id'];session['csrf']=secrets.token_hex(32)
            return redirect(url_for('index'))
        failures=(attempt['failures'] if attempt else 0)+1
        locked=(datetime.now(timezone.utc)+timedelta(minutes=15)).isoformat(timespec='seconds') if failures>=5 else None
        db().execute('INSERT INTO login_attempts(username,failures,locked_until) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until',(username,failures if failures<5 else 0,locked));db().commit()
        flash('Invalid username or password','error')
    if 'csrf' not in session: session['csrf']=secrets.token_hex(32)
    return render_template('login.html')
@app.post('/logout')
@login_required
def logout(): session.clear();return redirect(url_for('login'))
@app.get('/my-counts')
@login_required
def my_counts():
    if g.user['role']=='admin': return redirect(url_for('admin_dashboard'))
    rows=db().execute('''SELECT a.id assignment_id,rr.round recount_round,p.sku,ai.description_snapshot description,ai.location_snapshot location,au.name audit_name,
    (SELECT MAX(c.round) FROM counts c WHERE c.assignment_id=a.id) last_round
    FROM assignments a LEFT JOIN recount_requests rr ON rr.assignment_id=a.id JOIN audit_items ai ON ai.id=a.item_id JOIN audits au ON au.id=ai.audit_id
    JOIN parts p ON p.id=ai.part_id WHERE a.team_id=? AND au.status='active' ORDER BY au.id,p.location,p.sku''',(g.user['team_id'],)).fetchall()
    personal=db().execute('''SELECT ia.id assignment_id,p.sku,ai.description_snapshot description,ai.location_snapshot location,au.name audit_name,
        (SELECT 1 FROM individual_counts ic WHERE ic.assignment_id=ia.id) completed
        FROM individual_assignments ia JOIN audit_items ai ON ai.id=ia.item_id JOIN audits au ON au.id=ai.audit_id
        JOIN parts p ON p.id=ai.part_id WHERE ia.user_id=? AND au.status='active' ORDER BY au.id,p.sku''',(g.user['id'],)).fetchall()
    return render_template('counts.html',rows=rows,personal=personal)
@app.post('/count/<int:assignment_id>')
@login_required
def submit_count(assignment_id):
    if g.user['role']=='admin': abort(403)
    qty=integer(request.form.get('quantity'))
    row=db().execute('''SELECT a.id FROM assignments a JOIN audit_items ai ON ai.id=a.item_id JOIN audits au ON au.id=ai.audit_id WHERE a.id=? AND a.team_id=? AND au.status='active' ''',(assignment_id,g.user['team_id'])).fetchone()
    if not row: abort(404)
    if db().execute('SELECT 1 FROM recount_requests WHERE assignment_id=?',(assignment_id,)).fetchone(): abort(409,'Recount pending')
    try:
        db().execute('INSERT INTO counts(assignment_id,user_id,quantity,round,submitted_at) VALUES(?,?,?,1,?)',(assignment_id,g.user['id'],qty,now()))
        event('count_submitted',f'assignment={assignment_id} qty={qty} round=1');db().commit();flash('Count submitted')
    except sqlite3.IntegrityError: db().rollback();flash('Already submitted. Ask an administrator for a recount.','error')
    return redirect(url_for('my_counts'))
@app.get('/leaderboard')
@login_required
def leaderboard():
    rows=db().execute('''SELECT t.name,COUNT(a.id) assigned,COUNT(CASE WHEN EXISTS (SELECT 1 FROM counts c WHERE c.assignment_id=a.id) THEN 1 END) completed
    FROM teams t JOIN assignments a ON a.team_id=t.id
    JOIN audit_items ai ON ai.id=a.item_id JOIN audits au ON au.id=ai.audit_id AND au.status='active'
    GROUP BY t.id ORDER BY completed DESC,t.name''').fetchall()
    individual=db().execute('''SELECT t.name,COUNT(ia.id) assigned,COUNT(ic.id) completed FROM individual_assignments ia
      JOIN users u ON u.id=ia.user_id JOIN teams t ON t.id=u.team_id JOIN audit_items ai ON ai.id=ia.item_id
      JOIN audits au ON au.id=ai.audit_id AND au.status='active' LEFT JOIN individual_counts ic ON ic.assignment_id=ia.id
      GROUP BY t.id''').fetchall()
    merged={r['name']:{'name':r['name'],'assigned':r['assigned'],'completed':r['completed']} for r in rows}
    for r in individual:
        x=merged.setdefault(r['name'],{'name':r['name'],'assigned':0,'completed':0})
        x['assigned']+=r['assigned'];x['completed']+=r['completed']
    return render_template('leaderboard.html',rows=sorted(merged.values(),key=lambda x:(-x['completed'],x['name'])))
@app.get('/admin')
@admin_required
def admin_dashboard():
    audits=db().execute('SELECT * FROM audits ORDER BY id DESC').fetchall()
    teams=db().execute('SELECT * FROM teams ORDER BY name').fetchall()
    users=db().execute('SELECT u.id,u.username,u.role,u.active,u.approved,u.team_id,t.name team FROM users u LEFT JOIN teams t ON t.id=u.team_id ORDER BY u.username').fetchall()
    pending=db().execute('SELECT id,username FROM users WHERE approved=0 ORDER BY id DESC').fetchall()
    return render_template('admin.html',audits=audits,teams=teams,users=users,pending=pending)
@app.post('/admin/teams')
@admin_required
def create_team():
    name=request.form.get('name','').strip()
    if not name: abort(400)
    try: db().execute('INSERT INTO teams(name) VALUES(?)',(name,));event('team_created',name);db().commit()
    except sqlite3.IntegrityError: db().rollback();flash('Team already exists','error')
    return redirect(url_for('admin_dashboard'))
@app.post('/admin/users')
@admin_required
def create_user():
    username=request.form.get('username','').strip();password=request.form.get('password','');role=request.form.get('role')
    team_id=request.form.get('team_id') or None
    if not username or len(password)<12 or role not in ('admin','counter') or (role=='counter' and not team_id): abort(400,'Username, 12+ character password and team required')
    if team_id and not db().execute('SELECT 1 FROM teams WHERE id=?',(team_id,)).fetchone(): abort(400)
    try:
        db().execute('INSERT INTO users(username,password_hash,role,team_id) VALUES(?,?,?,?)',(username,generate_password_hash(password),role,team_id));event('user_created',username);db().commit()
    except sqlite3.IntegrityError: db().rollback();flash('Username already exists','error')
    return redirect(url_for('admin_dashboard'))
@app.post('/admin/audits')
@admin_required
def create_audit():
    name=request.form.get('name','').strip()
    if not name: abort(400)
    db().execute('INSERT INTO audits(name,created_at) VALUES(?,?)',(name,now()));event('audit_created',name);db().commit()
    return redirect(url_for('admin_dashboard'))
@app.get('/admin/audit/<int:audit_id>')
@admin_required
def audit_detail(audit_id):
    audit=db().execute('SELECT * FROM audits WHERE id=?',(audit_id,)).fetchone()
    if not audit: abort(404)
    teams=db().execute('SELECT * FROM teams ORDER BY name').fetchall()
    rows=db().execute('''SELECT a.id assignment_id,p.sku,ai.description_snapshot description,ai.location_snapshot location,ai.expected_qty,t.name team,
    (SELECT c.quantity FROM counts c WHERE c.assignment_id=a.id ORDER BY c.round DESC LIMIT 1) counted,
    (SELECT MAX(c.round) FROM counts c WHERE c.assignment_id=a.id) last_round
    FROM audit_items ai JOIN parts p ON p.id=ai.part_id LEFT JOIN assignments a ON a.item_id=ai.id LEFT JOIN teams t ON t.id=a.team_id
    WHERE ai.audit_id=? ORDER BY p.sku,t.name''',(audit_id,)).fetchall()
    counters=db().execute("SELECT id,username FROM users WHERE role='counter' AND active=1 AND approved=1 ORDER BY username").fetchall()
    individual=db().execute('''SELECT ia.id,p.sku,u.username,(SELECT ic.quantity FROM individual_counts ic WHERE ic.assignment_id=ia.id) counted
        FROM individual_assignments ia JOIN audit_items ai ON ai.id=ia.item_id JOIN parts p ON p.id=ai.part_id JOIN users u ON u.id=ia.user_id
        WHERE ai.audit_id=? ORDER BY p.sku,u.username''',(audit_id,)).fetchall()
    return render_template('audit.html',audit=audit,teams=teams,rows=rows,counters=counters,individual=individual)
@app.post('/admin/audit/<int:audit_id>/status')
@admin_required
def audit_status(audit_id):
    status=request.form.get('status')
    if status not in ('draft','active','closed'): abort(400)
    current=db().execute('SELECT status FROM audits WHERE id=?',(audit_id,)).fetchone()
    if not current: abort(404)
    if current['status']=='closed': abort(409,'Closed audits cannot be reopened')
    if current['status']=='active' and status=='draft': abort(409)
    db().execute('UPDATE audits SET status=? WHERE id=?',(status,audit_id));event('audit_status',f'{audit_id}: {status}');db().commit()
    return redirect(url_for('audit_detail',audit_id=audit_id))
@app.post('/admin/audit/<int:audit_id>/import')
@admin_required
def import_csv(audit_id):
    audit=db().execute('SELECT status FROM audits WHERE id=?',(audit_id,)).fetchone()
    if not audit or audit['status']!='draft': abort(409,'Import only allowed in draft audits')
    upload=request.files.get('file')
    if not upload: abort(400)
    try:
        reader=csv.DictReader(io.StringIO(upload.read().decode('utf-8-sig')))
        required={'sku','description','location','expected_qty'}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)): raise ValueError('Required headers: sku,description,location,expected_qty')
        rows=list(reader)
        if not rows or len(rows)>20000: raise ValueError('Provide 1–20,000 rows')
        seen=set();clean=[]
        for row in rows:
            sku=row['sku'].strip();desc=row['description'].strip();loc=row['location'].strip();qty=integer(row['expected_qty'].strip())
            if not sku or not desc or sku in seen: raise ValueError('Empty or duplicate SKU in CSV')
            seen.add(sku);clean.append((sku,desc,loc,qty))
        conn=db()
        for sku,desc,loc,qty in clean:
            conn.execute('INSERT INTO parts(sku,description,location) VALUES(?,?,?) ON CONFLICT(sku) DO UPDATE SET description=excluded.description,location=excluded.location',(sku,desc,loc))
            pid=conn.execute('SELECT id FROM parts WHERE sku=?',(sku,)).fetchone()['id']
            conn.execute('INSERT INTO audit_items(audit_id,part_id,expected_qty,description_snapshot,location_snapshot) VALUES(?,?,?,?,?) ON CONFLICT(audit_id,part_id) DO UPDATE SET expected_qty=excluded.expected_qty,description_snapshot=excluded.description_snapshot,location_snapshot=excluded.location_snapshot',(audit_id,pid,qty,desc,loc))
        event('inventory_imported',f'audit={audit_id} rows={len(clean)}');conn.commit();flash(f'Imported {len(clean)} parts')
    except (UnicodeError,csv.Error,ValueError) as e: db().rollback();flash(str(e),'error')
    return redirect(url_for('audit_detail',audit_id=audit_id))
@app.post('/admin/audit/<int:audit_id>/assign')
@admin_required
def assign(audit_id):
    if not db().execute("SELECT 1 FROM audits WHERE id=? AND status='draft'",(audit_id,)).fetchone(): abort(409)
    team_id=integer(request.form.get('team_id'))
    if not db().execute('SELECT 1 FROM teams WHERE id=?',(team_id,)).fetchone(): abort(400)
    skus=[x.strip() for x in request.form.get('skus','').split(',') if x.strip()]
    if skus:
        placeholders=','.join('?' for _ in skus)
        ids=db().execute(f'SELECT ai.id FROM audit_items ai JOIN parts p ON p.id=ai.part_id WHERE ai.audit_id=? AND p.sku IN ({placeholders})',(audit_id,*skus)).fetchall()
        if len(ids)!=len(set(skus)): abort(400,'One or more SKUs were not found in this audit')
    else:
        ids=db().execute('SELECT id FROM audit_items WHERE audit_id=?',(audit_id,)).fetchall()
    for row in ids: db().execute('INSERT OR IGNORE INTO assignments(item_id,team_id) VALUES(?,?)',(row['id'],team_id))
    event('team_assigned',f'audit={audit_id} team={team_id} items={len(ids)}');db().commit()
    return redirect(url_for('audit_detail',audit_id=audit_id))
@app.post('/admin/assignment/<int:assignment_id>/recount')
@admin_required
def recount(assignment_id):
    row=db().execute('''SELECT a.id,au.status FROM assignments a JOIN audit_items ai ON ai.id=a.item_id JOIN audits au ON au.id=ai.audit_id WHERE a.id=?''',(assignment_id,)).fetchone()
    if not row or row['status']!='active': abort(409)
    # A recount is only requested after an existing count. No previous count is deleted.
    latest=db().execute('SELECT MAX(round) n FROM counts WHERE assignment_id=?',(assignment_id,)).fetchone()['n']
    if latest is None: abort(409,'No count to recount')
    if db().execute('SELECT 1 FROM recount_requests WHERE assignment_id=?',(assignment_id,)).fetchone(): abort(409,'Recount already pending')
    # Recount requests tracked as events; one outstanding request per assignment.
    # Explicit separate table ensures unambiguous pending state.
    db().execute('INSERT INTO recount_requests(assignment_id,round,requested_at) VALUES(?,?,?) ON CONFLICT(assignment_id) DO UPDATE SET round=excluded.round,requested_at=excluded.requested_at',(assignment_id,latest+1,now()))
    event('recount_requested',f'assignment={assignment_id} round={latest+1}');db().commit()
    return redirect(request.referrer or url_for('admin_dashboard'))
@app.get('/admin/audit/<int:audit_id>/export')
@admin_required
def export(audit_id):
    if not db().execute('SELECT 1 FROM audits WHERE id=?',(audit_id,)).fetchone(): abort(404)
    rows=db().execute('''SELECT p.sku,ai.description_snapshot description,ai.location_snapshot location,t.name team,ai.expected_qty,
    (SELECT c.quantity FROM counts c WHERE c.assignment_id=a.id ORDER BY c.round DESC LIMIT 1) counted
    FROM audit_items ai JOIN parts p ON p.id=ai.part_id LEFT JOIN assignments a ON a.item_id=ai.id LEFT JOIN teams t ON t.id=a.team_id WHERE ai.audit_id=? ORDER BY p.sku,t.name''',(audit_id,)).fetchall()
    output=io.StringIO();writer=csv.writer(output);writer.writerow(['sku','description','location','team','expected_qty','counted_qty','variance','status'])
    for r in rows:
        qty=r['counted'];variance=qty-r['expected_qty'] if qty is not None else ''
        def safe_csv(value):
            if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@','\t','\r')): return '\''+value
            return value
        writer.writerow([safe_csv(r['sku']),safe_csv(r['description']),safe_csv(r['location']),safe_csv(r['team'] or ''),r['expected_qty'],qty if qty is not None else '',variance,'not counted' if qty is None else ('matched' if variance==0 else 'discrepancy')])
    personal=db().execute('''SELECT p.sku,ai.description_snapshot description,ai.location_snapshot location,u.username,ai.expected_qty,ic.quantity counted
        FROM individual_assignments ia JOIN audit_items ai ON ai.id=ia.item_id JOIN parts p ON p.id=ai.part_id
        JOIN users u ON u.id=ia.user_id LEFT JOIN individual_counts ic ON ic.assignment_id=ia.id WHERE ai.audit_id=? ORDER BY p.sku,u.username''',(audit_id,)).fetchall()
    for r in personal:
        qty=r['counted'];variance=qty-r['expected_qty'] if qty is not None else ''
        writer.writerow([safe_csv(r['sku']),safe_csv(r['description']),safe_csv(r['location']),safe_csv('Individual: '+r['username']),r['expected_qty'],qty if qty is not None else '',variance,'not counted' if qty is None else ('matched' if variance==0 else 'discrepancy')])
    event('audit_exported',f'audit={audit_id}');db().commit()
    return Response('\ufeff'+output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename=audit-{audit_id}.csv','Cache-Control':'no-store'})
def token_digest(token): return hashlib.sha256(token.encode()).hexdigest()
def new_token(kind,user_id=None):
    token=secrets.token_urlsafe(32)
    expires=(datetime.now(timezone.utc)+timedelta(hours=24)).isoformat(timespec='seconds')
    db().execute('INSERT INTO registration_tokens(token_hash,kind,user_id,created_by,expires_at) VALUES(?,?,?,?,?)',(token_digest(token),kind,user_id,session.get('uid'),expires))
    return token

def valid_token(token,kind):
    return db().execute('SELECT * FROM registration_tokens WHERE token_hash=? AND kind=? AND used_at IS NULL AND expires_at>?',(token_digest(token),kind,now())).fetchone()

@app.route('/register',methods=['GET','POST'])
def register():
    if os.environ.get('ALLOW_SELF_REGISTRATION','false').lower()!='true': abort(404)
    if request.method=='POST':
        username=request.form.get('username','').strip()[:128];password=request.form.get('password','')
        if len(username)<3 or len(password)<12: abort(400,'Username (3+) and password (12+) required')
        try:
            db().execute('INSERT INTO users(username,password_hash,role,approved) VALUES(?,?,?,0)',(username,generate_password_hash(password),'counter'))
            event('self_registration_pending',username);db().commit();flash('Registration received. An administrator must approve your account.');return redirect(url_for('login'))
        except sqlite3.IntegrityError: db().rollback();flash('Username unavailable','error')
    return render_template('register.html',invitation=False)

@app.route('/invite/<token>',methods=['GET','POST'])
def accept_invite(token):
    invite=valid_token(token,'invite')
    if not invite: abort(404,'Invitation expired or already used')
    if request.method=='POST':
        username=request.form.get('username','').strip()[:128];password=request.form.get('password','')
        if len(username)<3 or len(password)<12: abort(400)
        try:
            db().execute('INSERT INTO users(username,password_hash,role,approved) VALUES(?,?,?,1)',(username,generate_password_hash(password),'counter'))
            db().execute('UPDATE registration_tokens SET used_at=? WHERE id=? AND used_at IS NULL',(now(),invite['id']))
            event('invitation_accepted',username);db().commit();flash('Account created. Sign in to continue.');return redirect(url_for('login'))
        except sqlite3.IntegrityError: db().rollback();flash('Username unavailable','error')
    return render_template('register.html',invitation=True)

@app.post('/admin/invitations')
@admin_required
def create_invitation():
    token=new_token('invite');event('invitation_created','24h');db().commit()
    return render_template('generated_link.html',heading='One-time employee invitation',link=url_for('accept_invite',token=token,_external=True))

@app.post('/admin/users/<int:user_id>/approve')
@admin_required
def approve_user(user_id):
    u=db().execute("SELECT * FROM users WHERE id=? AND role='counter'",(user_id,)).fetchone()
    if not u: abort(404)
    db().execute('UPDATE users SET approved=1 WHERE id=?',(user_id,));event('user_approved',str(user_id));db().commit()
    return redirect(url_for('admin_dashboard'))

@app.post('/admin/users/<int:user_id>/team')
@admin_required
def set_user_team(user_id):
    team_id=integer(request.form.get('team_id'))
    if not db().execute('SELECT 1 FROM teams WHERE id=?',(team_id,)).fetchone(): abort(400)
    if not db().execute("SELECT 1 FROM users WHERE id=? AND role='counter'",(user_id,)).fetchone(): abort(404)
    db().execute('UPDATE users SET team_id=? WHERE id=?',(team_id,user_id));event('user_team_updated',f'user={user_id} team={team_id}');db().commit()
    return redirect(url_for('admin_dashboard'))

@app.post('/admin/users/<int:user_id>/reset')
@admin_required
def reset_user(user_id):
    u=db().execute('SELECT * FROM users WHERE id=? AND active=1',(user_id,)).fetchone()
    if not u: abort(404)
    token=new_token('reset',user_id);event('password_reset_link_created',str(user_id));db().commit()
    return render_template('generated_link.html',heading='One-time password reset link',link=url_for('reset_password',token=token,_external=True))

@app.route('/reset/<token>',methods=['GET','POST'])
def reset_password(token):
    record=valid_token(token,'reset')
    if not record: abort(404,'Reset link expired or already used')
    if request.method=='POST':
        password=request.form.get('password','')
        if len(password)<12: abort(400,'Password must have at least 12 characters')
        db().execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(password),record['user_id']))
        db().execute('UPDATE registration_tokens SET used_at=? WHERE id=?',(now(),record['id']))
        db().execute('DELETE FROM login_attempts WHERE username=(SELECT username FROM users WHERE id=?)',(record['user_id'],))
        event('password_reset_completed',str(record['user_id']));db().commit();session.clear();flash('Password updated. Sign in again.');return redirect(url_for('login'))
    return render_template('reset.html')

@app.post('/admin/audit/<int:audit_id>/assign-individual')
@admin_required
def assign_individual(audit_id):
    if not db().execute("SELECT 1 FROM audits WHERE id=? AND status='draft'",(audit_id,)).fetchone(): abort(409,'Only draft audits can be assigned')
    user_id=integer(request.form.get('user_id'))
    if not db().execute("SELECT 1 FROM users WHERE id=? AND role='counter' AND active=1 AND approved=1",(user_id,)).fetchone(): abort(400,'Choose an approved employee')
    skus=[x.strip() for x in request.form.get('skus','').split(',') if x.strip()]
    if skus:
        placeholders=','.join('?' for _ in skus)
        ids=db().execute(f'SELECT ai.id FROM audit_items ai JOIN parts p ON p.id=ai.part_id WHERE ai.audit_id=? AND p.sku IN ({placeholders})',(audit_id,*skus)).fetchall()
        if len(ids)!=len(set(skus)): abort(400,'One or more SKUs not found')
    else: ids=db().execute('SELECT id FROM audit_items WHERE audit_id=?',(audit_id,)).fetchall()
    for item in ids: db().execute('INSERT OR IGNORE INTO individual_assignments(item_id,user_id) VALUES(?,?)',(item['id'],user_id))
    event('individual_assigned',f'audit={audit_id} user={user_id} items={len(ids)}');db().commit()
    return redirect(url_for('audit_detail',audit_id=audit_id))

@app.post('/individual-count/<int:assignment_id>')
@login_required
def submit_individual_count(assignment_id):
    if g.user['role']!='counter': abort(403)
    qty=integer(request.form.get('quantity'))
    assignment=db().execute('''SELECT ia.id FROM individual_assignments ia JOIN audit_items ai ON ai.id=ia.item_id
        JOIN audits au ON au.id=ai.audit_id WHERE ia.id=? AND ia.user_id=? AND au.status='active' ''',(assignment_id,g.user['id'])).fetchone()
    if not assignment: abort(404)
    try:
        db().execute('INSERT INTO individual_counts(assignment_id,user_id,quantity,submitted_at) VALUES(?,?,?,?)',(assignment_id,g.user['id'],qty,now()))
        event('individual_count_submitted',f'assignment={assignment_id} qty={qty}');db().commit();flash('Individual count submitted')
    except sqlite3.IntegrityError: db().rollback();flash('Already counted','error')
    return redirect(url_for('my_counts'))

@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options']='nosniff';response.headers['X-Frame-Options']='DENY';response.headers['Referrer-Policy']='no-referrer';response.headers['Cache-Control']='no-store';response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'"
    return response

# Add separate durable recount request state (idempotent migration).
with app.app_context():
    init_db()
    db().execute('CREATE TABLE IF NOT EXISTS recount_requests(assignment_id INTEGER PRIMARY KEY REFERENCES assignments(id),round INTEGER NOT NULL,requested_at TEXT NOT NULL)');db().commit()

@app.post('/recount/<int:assignment_id>')
@login_required
def submit_recount(assignment_id):
    if g.user['role']=='admin': abort(403)
    qty=integer(request.form.get('quantity'))
    row=db().execute('''SELECT rr.round FROM recount_requests rr JOIN assignments a ON a.id=rr.assignment_id JOIN audit_items ai ON ai.id=a.item_id JOIN audits au ON au.id=ai.audit_id WHERE rr.assignment_id=? AND a.team_id=? AND au.status='active' ''',(assignment_id,g.user['team_id'])).fetchone()
    if not row: abort(404)
    try:
        db().execute('INSERT INTO counts(assignment_id,user_id,quantity,round,submitted_at) VALUES(?,?,?,?,?)',(assignment_id,g.user['id'],qty,row['round'],now()))
        db().execute('DELETE FROM recount_requests WHERE assignment_id=?',(assignment_id,));event('recount_submitted',f'assignment={assignment_id} round={row["round"]} qty={qty}');db().commit();flash('Recount submitted')
    except sqlite3.IntegrityError: db().rollback();flash('Recount already submitted','error')
    return redirect(url_for('my_counts'))

@app.cli.command('create-admin')
def create_admin():
    username=os.environ.get('ADMIN_USERNAME','admin');password=os.environ.get('ADMIN_PASSWORD','')
    if len(password)<12: raise RuntimeError('ADMIN_PASSWORD must contain at least 12 characters')
    if db().execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone(): raise RuntimeError('User already exists')
    db().execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',(username,generate_password_hash(password),'admin'));db().commit()
    print('Administrator created')
