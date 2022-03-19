__version__ = '0.0.18'

import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(name='psrt',
                 version=__version__,
                 author='Altertech',
                 author_email='pr@altertech.com',
                 description='PubSubRT Python connector',
                 long_description=long_description,
                 long_description_content_type='text/markdown',
                 url='https://github.com/alttch/psrt-py',
                 packages=setuptools.find_packages(),
                 include_package_data=True,
                 license='Apache License 2.0',
                 classifiers=[
                     'Programming Language :: Python :: 3',
                     'License :: OSI Approved :: Apache Software License',
                 ])
