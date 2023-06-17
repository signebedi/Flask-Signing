import os, datetime, unittest, time
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_signing import Signatures, RateLimitExceeded

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
        Test if the generate_key method returns a string with correct byte length,
        for keys of various byte lengths
        """

        for i in range(4, 256*2):
            with self.app.app_context():
                key = self.signatures.generate_key(length=i)

            # implemented the logic below because the string length is generally 1.3 times 
            # the byte length https://docs.python.org/3/library/secrets.html
            # self.assertEqual(len(key), self.signatures.byte_len)
            self.assertTrue(i < len(key) < 1.6*i)
            self.assertIsInstance(key, str)

    # def test_write_and_expire_key(self):
    #     """
    #     Test if a key can be written to the database and then successfully expired.
    #     """
    #     with self.app.app_context():
    #         key = self.signatures.write_key(scope='test')
    #     self.assertIsNotNone(Signing.query.filter_by(signature=key).first())
    #     self.signatures.expire_key(key)
    #     self.assertFalse(Signing.query.filter_by(signature=key).first().active)

    def test_write_and_expire_key_string_scope(self):
        with self.app.app_context():
            key = self.signatures.write_key(scope='test')
            Signing = self.signatures.get_model()
            self.assertIsNotNone(Signing.query.filter_by(signature=key).first())
            self.signatures.expire_key(key)
            self.assertFalse(Signing.query.filter_by(signature=key).first().active)

    def test_write_and_expire_key_list_scope(self):
        with self.app.app_context():
            key = self.signatures.write_key(scope=['test', 'task', 'tusk'])
            Signing = self.signatures.get_model()
            self.assertIsNotNone(Signing.query.filter_by(signature=key).first())
            self.signatures.expire_key(key)
            self.assertFalse(Signing.query.filter_by(signature=key).first().active)

    def test_verify_key(self):
        """
        Test if a signature can be successfully verified.
        """
        with self.app.app_context():
            key = self.signatures.write_key(scope='test')
            self.assertTrue(self.signatures.verify_key(signature=key, scope='test'))

            # Test expired key
            expired_key = self.signatures.write_key(scope='test', expiration=-1)
            self.assertFalse(self.signatures.verify_key(signature=expired_key, scope='test'))

            # Test non-existent key
            self.assertFalse(self.signatures.verify_key(signature='non-existent-key', scope='test'))

    def test_query_keys(self):
        """
        Test if the query_keys method returns correct records.
        """
        with self.app.app_context():
            key1 = self.signatures.write_key(scope='test1', email='test1@example.com')
            key2 = self.signatures.write_key(scope='test2', email='test2@example.com', active=True)
            key3 = self.signatures.rotate_key(key2)  # Generate a new key using rotate_key which assigns previous_key

            # Test querying by active status
            result = self.signatures.query_keys(active=True)
            self.assertTrue(all(record['active'] for record in result))

            # Test querying by scope
            result = self.signatures.query_keys(scope='test1')
            self.assertTrue(all(record['scope'] == ['test1'] for record in result))
            self.assertTrue(all(type(record['scope']) == list for record in result))

            # Test querying by email
            result = self.signatures.query_keys(email='test2@example.com')
            self.assertTrue(all(record['email'] == 'test2@example.com' for record in result))

            # # Test querying by previous_key
            result = self.signatures.query_keys(previous_key=key2)
            self.assertTrue(all(record['previous_key'] == key2 for record in result))
            self.assertTrue(len(result) == 1)            
            # if result is not False:
            #     self.assertTrue(all(record['previous_key'] == key2 for record in result))
            # else:
            #     self.fail("No records found for previous_key")

            # Check that the rotation does not occur if safe_mode is True and key is already rotated
            # with self.assertRaises(ValueError):
            #     self.signatures.rotate_key(key2)

            # Test querying by multiple fields
            result = self.signatures.query_keys(active=True, scope='test1', email='test1@example.com')
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['signature'], key1)

            # Test querying with no results
            result = self.signatures.query_keys(active=True, scope='non-existent-scope')
            self.assertFalse(result)


    def test_rotate_key(self):
        """
        Test if a key can be rotated and replaced with a new one.
        """
        with self.app.app_context():
            key = self.signatures.write_key(scope='test')
            Signing = self.signatures.get_model()
            signing_key = Signing.query.filter_by(signature=key).first()

            # Rotate the key
            new_key = self.signatures.rotate_key(key)

            # Check that the new key is different
            self.assertNotEqual(new_key, key)

            # Check that the old key is now inactive
            self.assertFalse(signing_key.active)

            # Check that the old key is now marked as rotated
            self.assertTrue(signing_key.rotated)

            # Check that the rotation does not occur if safe_mode is True and key is already rotated
            # with self.assertRaises(ValueError):
            #     self.signatures.rotate_key(key)

            self.assertFalse(self.signatures.rotate_key(key))

            # Check that the new key is not marked as rotated
            self.assertFalse(Signing.query.filter_by(signature=new_key).first().rotated)


            # Check that the new key is in the database and active
            new_signing_key = Signing.query.filter_by(signature=new_key).first()
            self.assertIsNotNone(new_signing_key)
            self.assertTrue(new_signing_key.active)

            # Check that the new key has the same properties as the old one
            self.assertEqual(signing_key.scope, new_signing_key.scope)
            self.assertEqual(signing_key.email, new_signing_key.email)
            # convert expiration to hours for comparison
            self.assertEqual((signing_key.expiration - datetime.datetime.utcnow()).seconds // 3600, 
                            (new_signing_key.expiration - datetime.datetime.utcnow()).seconds // 3600)

            # Check that the new key's previous_key is the old key
            self.assertEqual(new_signing_key.previous_key, key)

    def test_rotate_keys(self):
        """
        Test if multiple keys can be rotated.
        """
        with self.app.app_context():
            # Create keys that will expire soon
            soon_expire_key1 = self.signatures.write_key(scope='test1', expiration=1)
            soon_expire_key2 = self.signatures.write_key(scope='test2', expiration=1)

            # Create a key that won't expire soon
            late_expire_key = self.signatures.write_key(scope='test3', expiration=2)

            # Rotate keys
            self.signatures.rotate_keys(time_until=1)

            # Check that the keys that were about to expire have been rotated
            Signing = self.signatures.get_model()
            soon_expire_signing_key1 = Signing.query.filter_by(signature=soon_expire_key1).first()
            soon_expire_signing_key2 = Signing.query.filter_by(signature=soon_expire_key2).first()
            self.assertFalse(soon_expire_signing_key1.active)
            self.assertFalse(soon_expire_signing_key2.active)

            # Check that the key that wasn't about to expire hasn't been rotated
            late_expire_signing_key = Signing.query.filter_by(signature=late_expire_key).first()
            self.assertTrue(late_expire_signing_key.active)

            # Test rotating keys with a specific scope
            self.signatures.rotate_keys(time_until=2, scope='test3')

            # Check that the key with the specific scope has been rotated
            late_expire_signing_key = Signing.query.filter_by(signature=late_expire_key).first()
            self.assertFalse(late_expire_signing_key.active)

            # Get the new key that replaced the late_expire_key
            new_late_expire_key = Signing.query.filter_by(previous_key=late_expire_key).first()
            # Check that the new key's previous_key is the old key
            self.assertEqual(new_late_expire_key.previous_key, late_expire_key)


    def test_rate_limiting(self):
        """
        Test rate limiting functionality
        """

        with self.app.app_context():
            # Enable rate limiting
            self.signatures.rate_limiting = True
            self.signatures.rate_limiting_max_requests = 2
            self.signatures.rate_limiting_period = datetime.timedelta(seconds=2)

            # Generate a signature
            scope = ['example']
            signature = self.signatures.write_key(scope=scope, active=True)

            # Validate the key once, should return True
            self.assertTrue(self.signatures.verify_key(signature, scope))

            # Validate the key twice, should return True
            self.assertTrue(self.signatures.verify_key(signature, scope))

            # Now we expect a RateLimitExceeded exception because we are exceeding the rate limit
            with self.assertRaises(RateLimitExceeded):
                self.assertTrue(self.signatures.verify_key(signature, scope))

            # Wait for the rate limit period to pass
            time.sleep(2)

            # Validate the key again, should return True
            self.assertTrue(self.signatures.verify_key(signature, scope))


if __name__ == '__main__':
    unittest.main()