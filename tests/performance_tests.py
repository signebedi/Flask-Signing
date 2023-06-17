# tests/performance_tests.py

import cProfile
import pstats
import logging
import timeit
from io import StringIO

# Flask-specific requirements
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Session
from flask_signing import Signatures


# setup logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# create a file handler
handler = logging.FileHandler('performance.log')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # Use your actual database URI
app.secret_key = "Your_Key_Here"

with app.app_context():
    signatures = Signatures(app, byte_len=24, rate_limiting=True)

session = Session()

# Profiling helper function
def profile_function(func, name, *args, **kwargs):
    profiler = cProfile.Profile()
    profiler.enable()
    func(*args, **kwargs)
    profiler.disable()
    s = StringIO()
    sortby = 'cumulative'
    ps = pstats.Stats(profiler, stream=s).sort_stats(sortby)
    ps.print_stats()
    logger.info(f'Profiling of {name}:\n{s.getvalue()}')

def test_write_key_performance():
    with app.app_context():

        start_time = timeit.default_timer()
        signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)
        end_time = timeit.default_timer()
        elapsed_time = end_time - start_time
        logger.info(f'Performance of write_key: {elapsed_time} seconds')

def test_check_key_performance():
    with app.app_context():

        key = signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)
        start_time = timeit.default_timer()
        signatures.check_key(key, 'test')
        end_time = timeit.default_timer()
        elapsed_time = end_time - start_time
        logger.info(f'Performance of check_key: {elapsed_time} seconds')

def test_verify_key_performance():
    with app.app_context():
        signatures.rate_limiting = False  # Disable rate limiting for performance test

        key = signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)
        start_time = timeit.default_timer()
        signatures.verify_key(key, 'test')
        end_time = timeit.default_timer()
        elapsed_time = end_time - start_time
        logger.info(f'Performance of verify_key: {elapsed_time} seconds')

        signatures.rate_limiting = True  # Re-enable rate limiting after test


def test_expire_key_performance():
    with app.app_context():
        key = signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)
        start_time = timeit.default_timer()
        signatures.expire_key(key)
        end_time = timeit.default_timer()
        elapsed_time = end_time - start_time
        logger.info(f'Performance of expire_key: {elapsed_time} seconds')

def test_query_keys_performance():
    with app.app_context():
        # Prepare the data
        for i in range(10):
            signatures.write_key(scope='test', expiration=1, active=True, email='test'+str(i)+'@example.com', previous_key=None)

        # Run the test
        start_time = timeit.default_timer()
        signatures.query_keys(active=True, scope='test', email='test5@example.com')
        end_time = timeit.default_timer()
        elapsed_time = end_time - start_time
        logger.info(f'Performance of query_keys: {elapsed_time} seconds')

def test_get_all_performance():
    with app.app_context():
        start_time = timeit.default_timer()
        signatures.get_all()
        end_time = timeit.default_timer()
        elapsed_time = end_time - start_time
        logger.info(f'Performance of get_all: {elapsed_time} seconds')


def test_rotate_key_performance():
    with app.app_context():
        # Prepare the data
        key = signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)

        # Run the test
        start_time = timeit.default_timer()
        signatures.rotate_key(key)
        end_time = timeit.default_timer()
        elapsed_time = end_time - start_time
        logger.info(f'Performance of rotate_key: {elapsed_time} seconds')


def test_rotate_keys_performance():
    with app.app_context():
        # Prepare the data
        for i in range(10):
            signatures.write_key(scope='test', expiration=1, active=True, email='test'+str(i)+'@example.com', previous_key=None)

        # Run the test
        start_time = timeit.default_timer()
        signatures.rotate_keys(time_until=1, scope='test')
        end_time = timeit.default_timer()
        elapsed_time = end_time - start_time
        logger.info(f'Performance of rotate_keys: {elapsed_time} seconds')

# Here we add the cProfile tests

def profile_write_key_performance():
    with app.app_context():
        profile_function(signatures.write_key, 'write_key', scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)

def profile_check_key_performance():
    with app.app_context():
        key = signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)
        profile_function(signatures.check_key, 'check_key', key, 'test')

def profile_verify_key_performance():
    with app.app_context():
        signatures.rate_limiting = False  # Disable rate limiting for performance test

        key = signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)
        profile_function(signatures.verify_key, 'verify_key', key, 'test')

        signatures.rate_limiting = True  # Re-enable rate limiting after test

def profile_expire_key_performance():
    with app.app_context():
        key = signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)
        profile_function(signatures.expire_key, 'expire_key', key)

def profile_query_keys_performance():
    with app.app_context():
        # Prepare the data
        for i in range(10):
            signatures.write_key(scope='test', expiration=1, active=True, email='test'+str(i)+'@example.com', previous_key=None)

        # Run the test
        profile_function(signatures.query_keys, 'query_keys', active=True, scope='test', email='test5@example.com')

def profile_get_all_performance():
    with app.app_context():
        profile_function(signatures.get_all, 'get_all')

def profile_rotate_key_performance():
    with app.app_context():
        # Prepare the data
        key = signatures.write_key(scope='test', expiration=1, active=True, email='test@example.com', previous_key=None)

        # Run the test
        profile_function(signatures.rotate_key, 'rotate_key', key)

def profile_rotate_keys_performance():
    with app.app_context():
        # Prepare the data
        for i in range(10):
            signatures.write_key(scope='test', expiration=1, active=True, email='test'+str(i)+'@example.com', previous_key=None)

        # Run the test
        profile_function(signatures.rotate_keys, 'rotate_keys', time_until=1, scope='test')




if __name__ == '__main__':
    test_write_key_performance()
    test_check_key_performance()
    test_verify_key_performance()
    test_expire_key_performance()
    test_query_keys_performance()
    test_get_all_performance()
    test_rotate_key_performance()
    test_rotate_keys_performance()

    # profile checks
    profile_write_key_performance()
    profile_check_key_performance()
    profile_verify_key_performance()
    profile_expire_key_performance()
    profile_query_keys_performance()
    profile_get_all_performance()
    profile_rotate_key_performance()
    profile_rotate_keys_performance()

