from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), nullable=False)
    due_date = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:  # If user is logged in, redirect to their to-do list
        return redirect(url_for('todo_list'))
    return redirect(url_for('login'))  # Otherwise, redirect to login

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists and password matches
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('todo_list'))
        flash('Invalid credentials. Please try again.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        
        # Hash the password using pbkdf2:sha256
        hashed_password = generate_password_hash(password)  # No need to specify 'sha256'
        
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/todo', methods=['GET', 'POST'])
@login_required
def todo_list():
    if request.method == 'POST':
        task_content = request.form['task']
        due_date = request.form['due_date']
        new_task = Task(task=task_content, due_date=due_date, user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
        flash('Task added successfully!', 'success')
        return redirect(url_for('todo_list'))

    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('todo_list.html', tasks=tasks)

@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash('Unauthorized action.', 'error')
        return redirect(url_for('todo_list'))
    db.session.delete(task)
    db.session.commit()
    flash('Task completed!', 'success')
    return redirect(url_for('todo_list'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables inside app context
    app.run(debug=True)
