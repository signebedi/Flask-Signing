from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_signing import Signatures

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # Use your actual database URI

with app.app_context():
    signatures = Signatures(app, byte_len=24)


@app.route('/sign')
def sign():
    key = signatures.write_key_to_database(scope=['test', 'task', 'tusk'], expiration=1, active=True, email='test@example.com')
    return f'Key generated: {key}'

@app.route('/verify/<key>')
def verify(key):
    valid = signatures.verify_signature(signature=key, scope='test')
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
    all = signatures.all()
    return f'Response: {all}'