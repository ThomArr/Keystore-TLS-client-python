from setuptools import setup, Extension

setup(
    name="hsm_tls",
    version="0.1",
    ext_modules=[
        Extension(
            "hsm_tls",
            sources=["core/tls/hsm_tls.c"],
            libraries=["ssl", "crypto"],
        )
    ],
)