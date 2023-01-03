import os
import shutil

from setuptools import setup, find_packages

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(CUR_PATH, 'build')
if os.path.isdir(path):
    print('INFO del dir ', path)
    shutil.rmtree(path)

setup(
    name='nvd-cli',
    author='applerodite',
    version='0.1',
    packages=find_packages(),
    description='A command-line tool that wraps nvdlib (https://github.com/vehemont/nvdlib).',
    py_modules=['nvd'],
    include_package_data=True,
    exclude_package_data={'docs': ['README.md']},
    install_requires=[
        'nvdlib', 'click', 'prettytable'
    ],
    entry_points='''
        [console_scripts]
        nvd=nvd:search
    ''',

)
