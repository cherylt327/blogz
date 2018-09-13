from flask import Flask, request, redirect, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
import hashlib
import string


app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://blogz:test1234@localhost:3306/blogz'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)
app.secret_key = 'jskdfjlsdkfj123'


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    body = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, title, body, owner):
        self.title = title
        self.body = body
        self.owner = owner


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(500))
    blogs = db.relationship('Blog', backref='owner')

    def __init__(self, username, password):
        self.username = username
        self.password = password


@app.route('/', methods=['POST', 'GET'])
def blog_display():
    entries = Blog.query.all()
    
    return render_template('blog.html',title="Build-A-Blog", entries=entries)



@app.route('/newpost', methods=['POST', 'GET'])
def newpost():
    current_user = User.query.filter_by(username=session['username']).first()
    title = ''
    entry = ''
    
    title_error = ''
    body_error = ''

    if request.method == 'POST':
        title = request.form['title']
        entry = request.form['entry']
        
        if title == '':
            title_error = "Please fill in Title"

        if entry == '':
            body_error = "Please enter a blog entry"

        if entry and title != '':
            new_entry = Blog(title, entry, current_user)
            db.session.add(new_entry)
            db.session.commit()
            entry = Blog.query.filter_by(title=title).first()
            return render_template('blog_entry.html', entry=entry)

    return render_template('newpost.html', title_error=title_error, body_error=body_error, title=title, entry=entry )


@app.route('/blog', methods=['GET'])
def blog_page():
    blog_id= request.args.get('id')
    if  blog_id:
        entry = Blog.query.filter_by(id=blog_id).first()
        
        return render_template('blog_entry.html', entry=entry)
    return redirect('/')


@app.route('/register', methods=['POST', 'GET'])
def register():
    
          
    username_error = ''
    password_error = ''
    verify_error = ''

    if request.method == 'GET':
        return render_template("signup.html")

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password'] 
        verify = request.form['verify']

        if len(username) < 3 or len(username) > 20 or username.count(' ') > 0:
            username_error = 'Not a valid username'
            
        if len(password) < 3 or len(password) > 20 or password.count(' ') > 0:
            password_error = 'Not a valid password'
            
        if password != verify:
            verify_error = 'Passwords do not match'
            
        if username_error!='' or password_error!='' or verify_error!='':
            return render_template('signup.html', username=username, username_error=username_error,password_error=password_error,verify_error=verify_error)

        existing_user = User.query.filter_by(username=username).first()
        if not existing_user:
            hash = hashlib.sha256(str.encode(password)).hexdigest()
            new_user = User(username, hash)
            db.session.add(new_user)
            db.session.commit()
            session['username']=username
            return redirect('/')
       
        if existing_user:
            username_error = "That username already exists"
            return render_template('signup.html', username_error=username_error)




@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        unhashed = request.form['password']
        password = hashlib.sha256(str.encode(unhashed)).hexdigest()
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['username']=username
            return redirect('/')
        else:
            flash("Password Incorrect or User does not exist", "error")
    return render_template("login.html")


@app.route('/index', methods=['POST', 'GET'])
def authors():
    authors = User.query.all() 
    return render_template('index.html',title="Build-A-Blog", authors=authors)

@app.route('/author_entry', methods=['GET'])
def author_page():
    auth_id= request.args.get('id')
    if  auth_id:
        entry = Blog.query.filter_by(owner_id=auth_id).all()
        
        return render_template('author_entry.html', entry=entry)
    return redirect('/')







@app.before_request
def require_login():
    login_routes=['newpost']
    if request.endpoint in login_routes and 'username' not in session:
        return redirect('/login')

@app.route('/logout')
def logout():
    if 'username' in session:
        del session['username']
    return redirect('/')




if __name__ == '__main__':
    app.run()