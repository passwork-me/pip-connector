from setuptools import setup, find_packages


def readme():
    with open('README.md', 'r') as f:
        return f.read()


setup(
    name='passwork',
    version='0.1.1',
    description='Passwork API connector',
    long_description=readme(),
    long_description_content_type='text/markdown',
    packages=find_packages(),
    install_requires=[
        'requests>=2.31.0',
        'cryptography>=42.0.5',
        'loguru>=0.7.2'
    ],
    python_requires='>=3.10'
)
