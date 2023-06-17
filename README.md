![Signing logo](https://raw.githubusercontent.com/signebedi/Flask-Signing/master/docs/combined.png)

## Flask-Signing

[![License: BSD-3-Clause](https://img.shields.io/github/license/signebedi/Flask-Signing?color=dark-green)](https://github.com/signebedi/Flask-Signing/blob/master/LICENSE) 
[![PyPI version](https://badge.fury.io/py/Flask-Signing.svg)](https://pypi.org/project/flask-signing/)
[![Downloads](https://static.pepy.tech/personalized-badge/flask-signing?period=total&units=international_system&left_color=grey&right_color=brightgreen&left_text=Downloads)](https://pepy.tech/project/flask-signing)
[![Flask-Signing tests](https://github.com/signebedi/Flask-Signing/workflows/tests/badge.svg)](https://github.com/signebedi/Flask-Signing/actions)

a signing key extension for flask


### About

The Flask-Signing library is a useful tool for Flask applications that require secure and robust management of signing keys. Do you need to generate single-use tokens for one-time actions like email verification or password reset? Flask-Signing can handle that. Are you looking for a simple method for managing API keys? Look no further. 

### Installation

First, install the flask_signing package. You can do this with pip:

```bash
pip install flask_signing
```

### Usage

After you've installed the package, you can use it in your Flask application. Here's an example of how you might do this:

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_signing import Signatures

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # Use your actual database URI
app.secret_key = "Your_Key_Here"

with app.app_context():
    signatures = Signatures(app, byte_len=24)


@app.route('/sign')
def sign():
    key = signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com')
    return f'Key generated: {key}'

@app.route('/verify/<key>')
def verify(key):
    valid = signatures.verify_key(signature=key, scope='example')
    return f'Key valid: {valid}'

@app.route('/expire/<key>')
def expire(key):
    expired = signatures.expire_key(key)
    return f'Key expired: {expired}'
    
@app.route('/all')
def all():
    all = signatures.get_all()
    return f'Response: {all}'
```

In this example, a new signing key is generated and written to the database when you visit the /sign route, and the key is displayed on the page. Then, when you visit the /verify/<key> route (replace <key> with the actual key), the validity of the key is checked and displayed. You can expire a key using the /expire/<key> route, and view all records with the /all route.

Please note that this is a very basic example and your actual use of the flask_signing package may be more complex depending on your needs. It's important to secure your signing keys and handle them appropriately according to your application's security requirements.

### Developers

Contributions are welcome! You can read the developer docs at https://signebedi.github.io/Flask-Signing. If you're interested, review (or add to) the feature ideas at https://github.com/signebedi/Flask-Signing/issues.