from flask import Flask, request, redirect, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://build-a-blog:test1234@localhost:3306/build-a-blog'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)
app.secret_key = 'jskdfjlsdkfj123'


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    body = db.Column(db.Text)

    def __init__(self, title, body):
        self.title = title
        self.body = body


@app.route('/', methods=['POST', 'GET'])
def index():
    entries = Blog.query.all()
    
    return render_template('blog.html',title="Build-A-Blog", entries=entries)



@app.route('/newpost', methods=['POST', 'GET'])
def newpost():
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
            new_entry = Blog(title, entry)
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

  


if __name__ == '__main__':
    app.run()