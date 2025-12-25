
from setuptools import setup, find_packages

setup(
    name="bastion-firewall",
    version="2.0.18",
    description="Bastion Firewall - Application Firewall for Linux",
    author="Bastion Team",
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
            # Root helper for privileged operations (invoked via pkexec)
            'bastion-root-helper=bastion.root_helper:main',
        ],
    },
    data_files=[
        ('/etc/bastion', ['config.json']),
        ('/usr/share/applications', [
            'com.bastion.firewall.desktop',
            'bastion-control-panel.desktop',
        ]),
        ('/etc/xdg/autostart', ['bastion-tray.desktop']),
        ('/usr/share/polkit-1/actions', [
            'com.bastion.root-helper.policy',
        ]),
        ('/lib/systemd/system', ['bastion-firewall.service']),
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL License",
        "Operating System :: POSIX :: Linux",
    ],
)
