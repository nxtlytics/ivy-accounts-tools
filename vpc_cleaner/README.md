# vpc_cleaner

## Requirements

- python 3.8.1

## How to use it

```
cd path/to/this/repo
# Start of virtualenv setup section #
# skip this section if you already have a virtualenv for this repo has the modules required #
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
# End of virtualenv setup section #
(venv) $ AWS_PROFILE=profile-to-use python vpc_cleaner.py --help
Usage: vpc_cleaner.py [OPTIONS]

Options:
  --really-delete  Really delete VPC resources (scary!)
  --help           Show this message and exit.
```
