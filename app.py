import os
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, abort, flash, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bleach import clean

# --- Flask App Setup ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-very-secure-secret'  # use env var in production

# File uploads
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'docx'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Bleach Sanitization ---
ALLOWED_TAGS = ['a','abbr','acronym','b','blockquote','code','em','i',
                'li','ol','strong','ul','h1','h2','h3','p','img','pre',
                'table','thead','tbody','tr','th','td']
ALLOWED_ATTRS = {'*':['class','style'],'a':['href','title','target'],
                 'img':['src','alt','width','height']}
def sanitize_html(html: str) -> str:
    return clean(html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

# --- Models ---
class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    def set_password(self, pw):    self.password_hash = generate_password_hash(pw)
    def check_password(self, pw):  return check_password_hash(self.password_hash, pw)

class BlogInfo(db.Model):
    id      = db.Column(db.Integer, primary_key=True)
    title   = db.Column(db.String(100), nullable=False)
    tagline = db.Column(db.String(200), nullable=True)

class Post(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(200), nullable=False)
    body       = db.Column(db.Text,   nullable=False)
    filename   = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author     = db.relationship('User', backref='posts')

# --- Login Manager ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Context Processor ---
@app.context_processor
def inject_blog_info():
    info = BlogInfo.query.first()
    return dict(blog_info=info, current_user=current_user)

# --- DB Initialization ---
def create_tables():
    with app.app_context():
        db.create_all()
        if not BlogInfo.query.first():
            db.session.add(BlogInfo(title="My Awesome Blog", tagline=""))
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin')
            admin.set_password('password')
            db.session.add(admin)
        db.session.commit()

# --- Authentication Routes ---
@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        uname = request.form['username'].strip()
        pwd   = request.form['password']
        user  = User.query.filter_by(username=uname).first()
        if user and user.check_password(pwd):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- File Download Route ---
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# --- Blog CRUD Routes ---
@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/post/<int:id>')
def view_post(id):
    post = Post.query.get_or_404(id)
    return render_template('view_post.html', post=post)

@app.route('/create', methods=['GET','POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        if not title:
            abort(400, 'Title is required')
        body = sanitize_html(request.form.get('body',''))

        # Handle file upload
        file = request.files.get('file')
        filename = None
        if file and file.filename and allowed_file(file.filename):
            fname = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
            filename = fname

        p = Post(title=title, body=body, author=current_user, filename=filename)
        db.session.add(p); db.session.commit()
        return redirect(url_for('view_post', id=p.id))
    return render_template('edit_post.html', post=None)

@app.route('/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit_post(id):
    post = Post.query.get_or_404(id)
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        if not title:
            abort(400, 'Title is required')
        post.title = title
        post.body  = sanitize_html(request.form.get('body',''))

        file = request.files.get('file')
        if file and file.filename and allowed_file(file.filename):
            fname = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
            post.filename = fname

        db.session.commit()
        return redirect(url_for('view_post', id=post.id))
    return render_template('edit_post.html', post=post)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_post(id):
    post = Post.query.get_or_404(id)
    db.session.delete(post); db.session.commit()
    return redirect(url_for('index'))

# --- Admin Settings ---
@app.route('/admin/settings', methods=['GET','POST'])
@login_required
def admin_settings():
    info = BlogInfo.query.first()
    if request.method == 'POST':
        # Site settings
        new_title   = request.form.get('title','').strip()
        new_tagline = request.form.get('tagline','').strip()
        # Account settings
        new_user    = request.form.get('username','').strip()
        new_pass    = request.form.get('password','')
        confirm_pw  = request.form.get('confirm_password','')

        if not new_title:
            flash('Site title cannot be empty.', 'danger')
        else:
            info.title   = new_title
            info.tagline = new_tagline

            # Change username
            if new_user and new_user != current_user.username:
                if User.query.filter_by(username=new_user).first():
                    flash('Username already taken.', 'danger')
                else:
                    current_user.username = new_user

            # Change password
            if new_pass:
                if new_pass != confirm_pw:
                    flash('Passwords do not match.', 'danger')
                else:
                    current_user.set_password(new_pass)

            db.session.commit()
            flash('Settings updated.', 'success')
            return redirect(url_for('admin_settings'))

    return render_template('settings.html', info=info)

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)

