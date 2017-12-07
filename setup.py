from distutils.core import setup


setup(
    name='nmap_vscan',
    version='1.0.1',
    author='Nixawk',
    author_email='',
    license='MIT',
    url='https://github.com/nixawk/nmap_vscan',
    description='Nmap Vscan',
    long_description=open('README.md').read(),
    keywords='nmap vscan fingerprint recognition security',
    packages=['nmap_vscan'],

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 2 :: Only',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)

# https://pypi.python.org/pypi?%3Aaction=list_classifiers