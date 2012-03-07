import os
import subprocess
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def build_macdll():
    print("Building libmacdll.dylib...")
    print("-" * 30)
    script = """
    cd MacOSX/macdll
    xcodebuild -target macdll -configuration {0}
    cp -f build/{0}/libmacdll.dylib ../../pydbg
    cp -f build/{0}/libmacdll.dylib ../../utils
    """
    build_config = "Debug"
    res = subprocess.call(script.format(build_config), shell=True)
    print("-" * 30)
    if res != 0:
        print("failed to build macdll")
        exit(res)

build_macdll()

setup(
    name = "pydbg",
    version = "0.0.1",
    author = "fG!",
    author_email = "reverser@put.as",
    description = ("Port of PyDbg to Mac OS X on x86_64"),
    license = "GPL",
    keywords = "pydbg debug 64-bit",
    url = "http://github.com/gdbinit/pydbg64",
    packages=['pydbg'],
    install_requires = ['pydot', 'wxPython', 'mysql-python'],
    long_description=read('README'),
    package_data = {
        'pydbg': ['*.dylib'],
    },
)
