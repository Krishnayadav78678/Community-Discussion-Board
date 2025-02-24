import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,TextAreaField
from wtforms.validators import InputRequired, Length
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
class PostForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired()])
    content = TextAreaField('Content', validators=[InputRequired()])
    submit = SubmitField('Post')
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    submit = SubmitField('Login')

# Routes
@app.route('/')
def home():
    posts = db.session.query(Post, User).join(User).all()  # Join Post and User tables
    return render_template('home.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating your account.', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        flash('Login failed! Check your credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = PostForm()  # Create an instance of the form
    if form.validate_on_submit():  # Validate the form on submission
        try:
            post = Post(title=form.title.data, content=form.content.data, user_id=current_user.id)
            db.session.add(post)
            db.session.commit()
            flash('Post created successfully!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating the post.', 'danger')
    return render_template('create.html', form=form)  # Pass the form to the template

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        room = request.form['room']
        session['room'] = room
        return redirect(url_for('chat_room'))
    return render_template('chat.html')

@app.route('/chat_room')
@login_required
def chat_room():
    if 'room' not in session:
        return redirect(url_for('chat'))
    return render_template('chat_room.html', room=session['room'], username=current_user.username)

# Socket.IO Events
active_users = {}
active_rooms = {}

@socketio.on('join')
def handle_join(data):
    username = data['username']
    room = data['room']
    join_room(room)

    if room not in active_users:
        active_users[room] = []
    if username not in active_users[room]:
        active_users[room].append(username)

    if room not in active_rooms:
        active_rooms[room] = 1
    else:
        active_rooms[room] += 1

    emit('message', f"{username} has joined the room!", room=room)
    emit('active_users', active_users[room], room=room)
    emit('update_rooms', active_rooms, broadcast=True)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    emit('message', f"{data['username']}: {data['message']}", room=room)

@socketio.on('leave')
def handle_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)

    if room in active_users and username in active_users[room]:
        active_users[room].remove(username)

    if room in active_rooms:
        active_rooms[room] -= 1
        if active_rooms[room] == 0:
            del active_rooms[room]

    emit('message', f"{username} has left the room!", room=room)
    emit('active_users', active_users[room], room=room)
    emit('update_rooms', active_rooms, broadcast=True)
    
@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)  # Find the post or return 404 if not found

    # Ensure the current user is the owner of the post
    if post.user_id != current_user.id:
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('create'))

    try:
        db.session.delete(post)  # Delete the post
        db.session.commit()  # Commit the change to the database
        flash('Post deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the post.', 'danger')

    return redirect(url_for('create'))  # Redirect back to the create page
@socketio.on('get_active_rooms')
def send_active_rooms():
    emit('update_rooms', active_rooms)

# Initialize Database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    socketio.run(app, debug=True)