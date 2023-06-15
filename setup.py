from setuptools import setup, find_packages

# Read README for long_description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# # Read requirements.txt for install_requires
# with open("requirements.txt", "r", encoding="utf-8") as fr:
#     install_requires = fr.read().splitlines()

setup(
    name='flask_signing',
    version='0.4.1',
    url='https://github.com/signebedi/Flask-Signing',
    author='Sig Janoska-Bedi',
    author_email='signe@atreeus.com',
    description='a signing key extension for flask',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        'Flask<3.0.0',
        'Flask-SQLAlchemy<4.0.0',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
