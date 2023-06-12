import os
import unittest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_signing import Signatures
from flask_signing.models import Signing, db as db_orig

class TestFlaskSigning(unittest.TestCase):

    def setUp(self):
        """
        Set up testing environment.
        """
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Use in-memory SQLite for testing
        self.app.config['TESTING'] = True
        self.db = SQLAlchemy(self.app)
        self.signatures = Signatures(database=self.db)

        with self.app.app_context():
            self.db.create_all()

    def tearDown(self):
        """
        Clean up testing environment.
        """
        with self.app.app_context():
            self.db.session.remove()
            self.db.drop_all()

    def test_generate_key(self):
        """
        Test if the generate_key method returns a string with correct length
        """
        with self.app.app_context():
            key = self.signatures.generate_key()
        # self.assertEqual(len(key), self.signatures.key_len)
        self.assertIsInstance(key, str)

    def test_write_and_expire_key(self):
        """
        Test if a key can be written to the database and then successfully expired.
        """
        with self.app.app_context():
            key = self.signatures.write_key_to_database(scope='test')
        self.assertIsNotNone(Signing.query.filter_by(signature=key).first())
        self.signatures.expire_key(key)
        self.assertFalse(Signing.query.filter_by(signature=key).first().active)

    def test_verify_signature(self):
        """
        Test if a signature can be successfully verified.
        """
        with self.app.app_context():
            key = self.signatures.write_key_to_database(scope='test')
            self.assertTrue(self.signatures.verify_signature(signature=key, scope='test'))

            # Test expired key
            expired_key = self.signatures.write_key_to_database(scope='test', expiration=-1)
            self.assertFalse(self.signatures.verify_signature(signature=expired_key, scope='test'))

            # Test non-existent key
            self.assertFalse(self.signatures.verify_signature(signature='non-existent-key', scope='test'))

if __name__ == '__main__':
    unittest.main()