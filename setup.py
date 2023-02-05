from setuptools import setup, find_packages


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name="elflepton",
    version="1.0.2",
    license="MIT",
    description="Parse an ELF binary with corrupted ELF headers.",
    long_description=readme(),
    long_description_content_type='text/markdown',
    author="Nikhil Ashok Hegde",
    author_email="nikhilhegde20@gmail.com",
    url="https://github.com/nikhilh-20/lepton",
    packages=find_packages()
)
