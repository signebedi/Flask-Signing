from flask import Flask, jsonify
from flask_signing import Signatures, RateLimitExceeded

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # Use your actual database URI
app.secret_key = "Your_Key_Here"

with app.app_context():
    signatures = Signatures(app, byte_len=24, rate_limiting=True)


@app.route('/sign')
def sign():
    key = signatures.write_key(scope=['test', 'task', 'tusk'], expiration=1, active=True, email='test@example.com')
    return f'Key generated: {key}'

@app.route('/verify/<key>')
def verify(key):
    try:
        valid = signatures.verify_key(signature=key, scope='test')
        return f'Key valid: {valid}'
    except RateLimitExceeded:
        return "Rate limit exceeded"


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
    return jsonify(all)

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

if __name__=="__main__":
    app.run(debug=True)