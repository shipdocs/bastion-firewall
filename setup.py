
from setuptools import setup, find_packages

setup(
    name="bastion-firewall",
    version="2.0.37",
    description="Bastion Firewall - Application Firewall for Linux",
    author="Bastion Team",
    packages=find_packages(),
    install_requires=[
        "PyQt6>=6.0.0",
    ],
    scripts=[
        "bastion-gui.py",
        "bastion_control_panel.py"
    ],
    # Note: entry_points removed because script files use hyphens (bastion-daemon.py)
    # which cannot be imported as Python modules. Use scripts[] instead.
    data_files=[
        ('/usr/share/applications', ['com.bastion.firewall.desktop']),
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL License",
        "Operating System :: POSIX :: Linux",
    ],
)
