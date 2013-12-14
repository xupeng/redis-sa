from setuptools import setup, find_packages
import sys, os

version = '0.1'

install_requires = [
    'pcap',
    'dpkt',
]
if sys.version_info < (2, 7):
    install_requires.append('argparse')

setup(name='redis-sa',
      version=version,
      description="A redis sniffer & analyzer",
      long_description=open('README.rst').read(),
      classifiers=['Topic :: Database',
                   'Topic :: Utilities',
                   'Topic :: System :: Systems Administration',
                   'Programming Language :: Python',],
      keywords='',
      author='Xupeng Yun',
      author_email='xupeng@xupeng.me',
      url='https://github.com/xupeng/redis-sa',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=install_requires,
      entry_points={
          'console_scripts': [
              'redis-sniffer = redis_sa.sniffer:main',
          ],
      },
      dependency_links=[
          'git+git://github.com/xupeng/pypcap.git@1.1#egg=pcap-1.1',
          'http://dpkt.googlecode.com/files/dpkt-1.7.tar.gz#egg=dpkt-1.7',
      ]
      )
