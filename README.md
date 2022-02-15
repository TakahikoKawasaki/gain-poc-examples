# Examples for the GAIN Ecosystem

This repository contains a working client for the GAIN Proof-of-Concept.

![GAIN launcher page](screenshot.png "GAIN launcher")

## Setup
```
git clone https://github.com/yescom/gain-examples.git
pip3 install -r requirements.txt
```

## Usage
Set up identity providers and the claims to be requested in `config/gain.yml`.

Ensure that the key and cert files referenced in the configuration file can be found - paths are resolved relative to the repository root.

Then run:
```
python3 examples/gain.py
```
... and point your browser to http://localhost:3000/
