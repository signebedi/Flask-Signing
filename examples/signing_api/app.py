"app.py"

__version__ = "0.1.0"

from flask import Flask, request, render_template, flash
from flask_signing import Signatures

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # Use your actual database URI
app.secret_key = "Your_Key_Here"

with app.app_context():
    signatures = Signatures(app, byte_len=32)

@app.route('/api/create', methods=['GET', 'POST'])
def create_api_key():
    if request.method == 'POST':
        email = request.form['email']
        _signature = signatures.query_keys(active=1, email=email)
        try:
            assert not _signature
            signature = signatures.write_key(scope='api', expiration=365, active=True, email=email)
            flash(f'API Key created successfully: {signature}', 'info')
        except Exception as e:
            print(e)
            flash('API Key already exists for this email.', 'warning')
    return render_template('create_api_key.html.jinja')


if __name__ == '__main__':
    app.run(debug=True)