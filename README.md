## Flask-Signing
a signing key extension for flask

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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'  # Use your actual database URI

db = SQLAlchemy(app)
signatures = Signatures(database=db)

@app.route('/sign')
def sign():
    key = signatures.write_key_to_database(scope='example')
    return f'Key generated: {key}'

@app.route('/verify/<key>')
def verify(key):
    valid = signatures.verify_signature(signature=key, scope='example')
    return f'Key valid: {valid}'
```

In this example, a new signing key is generated and written to the database when you visit the /sign route, and the key is displayed on the page. Then, when you visit the /verify/<key> route (replace <key> with the actual key), the validity of the key is checked and displayed.

Remember to replace 'sqlite:////tmp/test.db' with your actual SQLAlchemy database URI.

Also, ensure you initialize your database and create the necessary tables before running your app, e.g.:

```python
from flask_signing.models import Signing

@app.before_first_request
def create_tables():
    db.create_all()
```

Please note that this is a very basic example and your actual use of the flask_signing package may be more complex depending on your needs. It's important to secure your signing keys and handle them appropriately according to your application's security requirements.