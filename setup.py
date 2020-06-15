from setuptools import setup

setup(
    name='clamsb',
    version='v4.0',
    author='Kevin Lin',
    author_email='kevlin2@cisco.com',
    description='acquires the Google Safebrowsing Lists through the Google Safebrowsing V4 API and packages the data into a ClamAV GDB',
    packages=['clamsb'],
    python_requires='>=2.7',
    install_requires=[
        'mysqlclient',
        'sqlalchemy',
        'google-api-python-client',
        'apacheconfig',
    ],
    scripts=['clamsbwrite.py', 'clamsbsync.py'],
)

