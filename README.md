# Examples for pyyes

This repository contains examples for the GAIN Proof-of-Concept.

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

