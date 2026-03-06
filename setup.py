from setuptools import setup, Extension
import os
import glob

# ML-KEM-768 (Kyber768) source files - auto-discover all .c files
import glob
kyber_sources = glob.glob('src/kyber768/*.c')

# ML-DSA-65 (Dilithium3) source files - auto-discover all .c files  
dilithium_sources = glob.glob('src/dilithium3/*.c')

# Common files (fips202 for SHAKE) - auto-discover
common_sources = glob.glob('src/common/*.c')

# Main wrapper
wrapper_sources = ['src/pqc_wrapper.c']

# Combine all sources
all_sources = wrapper_sources + kyber_sources + dilithium_sources + common_sources

pqc_module = Extension(
    'pqc_native',
    sources=all_sources,
    include_dirs=[
        'src/kyber768',
        'src/dilithium3',
        'src/common',
    ],
    extra_compile_args=['-O3', '-std=c99', '-Wall'] if os.name != 'nt' else ['/W3'],
    libraries=['advapi32'] if os.name == 'nt' else [],  # Windows crypto library
)

setup(
    name='pqc-native',
    version='1.0.0',
    description='Post-Quantum Cryptography with Kyber and Dilithium',
    author='Your Name',
    ext_modules=[pqc_module],
    packages=['pqc'],
    install_requires=[
        'boto3>=1.26.0',
    ],
    python_requires='>=3.7',
)