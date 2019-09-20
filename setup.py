#!/usr/bin/env python

import io
import os
import re
from collections import OrderedDict

from setuptools import find_packages, setup


def get_long_description():
    for filename in ('README.rst',):
        with io.open(filename, 'r', encoding='utf-8') as f:
            yield f.read()


def get_version(package):
    with io.open(os.path.join(package, '__init__.py')) as f:
        pattern = r'^__version__ = [\'"]([^\'"]*)[\'"]'
        return re.search(pattern, f.read(), re.MULTILINE).group(1)


setup(
    name='django-ariadne-jwt',
    version=get_version('django_ariadne_jwt'),
    license='MIT',
    description='JSON Web Token for Django Ariadne',
    long_description='\n\n'.join(get_long_description()),
    author='marco-btree',
    author_email='marco@binarytree-software.com',
    maintainer='marco-btree',
    url='https://github.com/binarytree-software/django-ariadne-jwt',
    project_urls=OrderedDict((
        (
            'Issues',
            'https://github.com/binarytree-software/django-ariadne-jwt/issues'
        ),
    )),
    packages=find_packages(exclude=['tests*']),
    install_requires=[
        'ariadne>=0.6.0',
        'Django>=2.0.0',
        'PyJWT>=1.5.0',
    ],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Framework :: Django',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Framework :: Django :: 2.2',
    ],
    zip_safe=False,
    tests_require=[
        'ariadne>=0.6.0',
        'Django>=2.0.0',
        'PyJWT>=1.5.0',
    ],
    package_data={
        'ardiadne_django_jwt': [
            'locale/*/LC_MESSAGES/django.po',
            'locale/*/LC_MESSAGES/django.mo',
        ],
    },
)
