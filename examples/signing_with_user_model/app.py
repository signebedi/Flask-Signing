from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_signing import Signatures

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # Use your actual database URI
app.config['SECRET_KEY'] = 'Your_Key_Here'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(80))

with app.app_context():
    # You should instantiate the Signatures class prior to calling 
    # create_all() on your db instance
    signatures = Signatures(app, db=db, byte_len=24, rate_limiting=True)
    db.create_all()

@app.route('/')
@login_required
def home():
    return 'The current user is ' + current_user.username

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = generate_password_hash(request.form.get('password'))

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/sign')
def sign():
    key = signatures.write_key(scope=['test', 'task', 'tusk'], expiration=1, active=True, email='test@example.com')
    return f'Key generated: {key}'

@app.route('/verify/<key>')
def verify(key):
    valid = signatures.verify_key(signature=key, scope='test')
    return f'Key valid: {valid}'

@app.route('/expire/<key>')
def expire(key):
    expired = signatures.expire_key(key)
    return f'Key expired: {expired}'


@app.route('/query')
def query():
    query = signatures.query_keys(scope='test')
    return f'Response: {query}'

@app.route('/all')
def all():
    all = signatures.get_all()
    return f'Response: {all}'

@app.route('/rotate/<key>', methods=['GET'])
def rotate_key(key):
    try:
        new_key = signatures.rotate_key(key, expiration=1/60)
        if new_key:
            return f'Old key: {key} has been replaced with new key: {new_key}'
        else:
            return f'Failed to rotate key: {key}', 400
    except Exception as e:
        return str(e), 500

@app.route('/rotate_keys/<int:time_until>', methods=['GET'])
def rotate_keys(time_until):
    try:
        success = signatures.rotate_keys(time_until)
        if success:
            return f'Successfully rotated keys expiring in next {time_until} hours'
        else:
            return 'Failed to rotate keys', 400
    except Exception as e:
        return str(e), 500


# for debug purposes, you can spit out the contents of the signing and user tables
@app.route('/show_data', methods=['GET'])
def show_data():
    data = {}
    for table in db.metadata.sorted_tables:
        data[str(table)] = [{column.name: getattr(row, column.name) for column in table.columns} for row in db.session.query(table).all()]
    return jsonify(data)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == "__main__":
    app.run(debug=True)