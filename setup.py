from setuptools import setup, find_packages
# from flask_signing._metadata import __version__ as version

def read_version():
    with open('flask_signing/__metadata__.py', 'r') as f:
        lines = f.readlines()

    for line in lines:
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]

    raise RuntimeError("Unable to find version string.")

version = read_version()

# Read README for long_description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# # Read requirements.txt for install_requires
with open('requirements.txt', encoding="utf-8") as f:
    install_requires = f.read().splitlines()

setup(
    name='flask_signing',
    version=version,
    url='https://github.com/signebedi/Flask-Signing',
    author='Sig Janoska-Bedi',
    author_email='signe@atreeus.com',
    description='a signing key extension for flask',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=install_requires,
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
