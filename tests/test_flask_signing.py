import os
import unittest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_signing import Signatures

class TestFlaskSigning(unittest.TestCase):

    def setUp(self):
        """
        Set up testing environment.
        """
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['TESTING'] = True

        with self.app.app_context():
            self.signatures = Signatures(app=self.app)
            self.db = self.signatures.db
            self.db.create_all()

    def tearDown(self):
        """
        Clean up testing environment.
        """
        with self.app.app_context():
            self.db.session.remove()
            self.db.drop_all()  # drop all tables in the database


    def test_generate_key(self):
        """
        Test if the generate_key method returns a string with correct byte length
        """
        with self.app.app_context():
            key = self.signatures.generate_key()

        # implemented the logic below because the string length is generally 1.3 times 
        # the byte length https://docs.python.org/3/library/secrets.html
        # self.assertEqual(len(key), self.signatures.byte_len)
        self.assertTrue(self.signatures.byte_len < len(key) < 1.6*self.signatures.byte_len)
        self.assertIsInstance(key, str)

    # def test_write_and_expire_key(self):
    #     """
    #     Test if a key can be written to the database and then successfully expired.
    #     """
    #     with self.app.app_context():
    #         key = self.signatures.write_key_to_database(scope='test')
    #     self.assertIsNotNone(Signing.query.filter_by(signature=key).first())
    #     self.signatures.expire_key(key)
    #     self.assertFalse(Signing.query.filter_by(signature=key).first().active)

    def test_write_and_expire_key(self):
        with self.app.app_context():
            key = self.signatures.write_key_to_database(scope='test')
            Signing = self.signatures.get_model()
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