
from setuptools import setup, find_packages

setup(
    name="douane-firewall",
    version="2.0.0",
    description="Application Firewall for Linux / Douane Application Firewall for Linux",
    author="Douane Team",
    packages=find_packages(),
    install_requires=[
        "psutil>=5.9.0",
        "tabulate>=0.9.0",
        "NetfilterQueue>=1.1.0",
        "scapy>=2.5.0",
        "pystray>=0.19.0",
        "Pillow>=9.0.0",
    ],
    scripts=[
        "douane-daemon.py",
        "douane-gui-client.py", 
        "douane_control_panel.py"
    ],
    entry_points={
        'console_scripts': [
            'douane-daemon=douane_daemon:main',
            'douane-gui=douane_gui_client:main',
            'douane-control-panel=douane_control_panel:main',
        ],
    },
    data_files=[
        ('/etc/douane', ['config.json']),
        ('/usr/share/applications', ['douane-firewall.desktop']),
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL License",
        "Operating System :: POSIX :: Linux",
    ],
)
