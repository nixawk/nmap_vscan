from distutils.core import setup


setup(
    name='nmap_vscan',
    version='1.0.0',
    author='Nixawk',
    author_email='',
    license='MIT',
    url='https://github.com/nixawk/nmap_vscan',
    description='Nmap Vscan',
    long_description='Nmap Service and Application Version Detection',
    keywords='nmap vscan security',
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