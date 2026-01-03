
from setuptools import setup, find_packages

setup(
    name="bastion-firewall",
    version="2.0.26",
    description="Bastion Firewall - Application Firewall for Linux",
    author="Bastion Team",
    packages=find_packages(),
    install_requires=[
        "psutil>=5.9.0",
        "tabulate>=0.9.0",
        "NetfilterQueue>=1.1.0",
        "scapy>=2.5.0",
        "PyQt6>=6.0.0",
        "pystray>=0.19.0",
        "Pillow>=10.2.0",
    ],
    scripts=[
        "bastion-daemon.py",
        "bastion-gui.py",
        "bastion_control_panel.py"
    ],
    # Note: entry_points removed because script files use hyphens (bastion-daemon.py)
    # which cannot be imported as Python modules. Use scripts[] instead.
    data_files=[
        ('/etc/bastion', ['config.json']),
        ('/usr/share/applications', ['bastion-firewall.desktop']),
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL License",
        "Operating System :: POSIX :: Linux",
    ],
)
