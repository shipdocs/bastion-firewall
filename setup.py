
from setuptools import setup, find_packages

setup(
    name="bastion-firewall",
    version="2.0.18",
    description="Application Firewall for Linux / Douane Application Firewall for Linux",
    author="Douane Team",
    packages=find_packages(),
    install_requires=[
        "psutil>=5.9.0",
        "tabulate>=0.9.0",
        "NetfilterQueue>=1.1.0",
        "scapy>=2.5.0",
    ],
    scripts=[
        "bastion-daemon.py",
        "bastion-gui.py", 
        "bastion_control_panel.py"
    ],
    entry_points={
        'console_scripts': [
            'bastion-daemon=douane_daemon:main',
            'douane-gui=douane_gui_client:main',
            'bastion-control-panel=bastion_control_panel:main',
        ],
    },
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
