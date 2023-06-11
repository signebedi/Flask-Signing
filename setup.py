from setuptools import setup, find_packages

setup(
    name='flask_signing',
    version='0.1.0',
    url='https://github.com/signebedi/Flask-Signing',
    author='Sig Janoska-Bedi',
    author_email='signe@atreeus.com',
    description='a signing key extension for flask',
    packages=find_packages(),  
    install_requires=[
        'Flask<3.0.0',
        'Flask-SQLAlchemy<4.0.0',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
