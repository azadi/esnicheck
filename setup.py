import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

install_requires = [
    "dnspython>=1.16.0",
]

setuptools.setup(
    name="esnicheck",
    version="0.1.0",
    author="Sukhbir Singh",
    author_email="sukhbir@riseup.net",
    description="A Python module that checks hostnames for ESNI support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/azadi/esnicheck/",
    packages=setuptools.find_packages(),
    packages_dir={"": "esnicheck"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 3 - Alpha",
        "Topic :: Security :: Cryptography",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
    install_requires=install_requires,
)
