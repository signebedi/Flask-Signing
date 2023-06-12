from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_signing import Signatures
from flask_signing.models import Signing

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # Use your actual database URI

db = SQLAlchemy(app)
with app.app_context():
    db.create_all()

signatures = Signatures(database=db)

@app.route('/sign')
def sign():
    key = signatures.write_key_to_database(scope='example')
    return f'Key generated: {key}'

@app.route('/verify/<key>')
def verify(key):
    valid = signatures.verify_signature(signature=key, scope='example')
    return f'Key valid: {valid}'