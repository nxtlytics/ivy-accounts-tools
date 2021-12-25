# Creates infrastructure s3 buckets per sysenv

## How to use it

```
$ cd path/to/this/repo
$ AWS_PROFILE=profile-to-use poetry run python infra_buckets/infra_buckets.py --help
usage: infra_buckets.py [-h] -c PHASE -p PURPOSE [-t IVY_TAG] [-r REGIONS] [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG}]

Creates infrastructure s3 buckets per sysenv

optional arguments:
  -h, --help            show this help message and exit
  -c PHASE, --phase PHASE
                        AWS Sub Account Phase (prod, dev, stage, ...)
  -p PURPOSE, --purpose PURPOSE
                        AWS Sub Account purpose (app, tools, sandbox, ...)
  -t IVY_TAG, --ivy-tag IVY_TAG
                        Ivy tag also known as namespace
  -r REGIONS, --regions REGIONS
                        Comma-separated list of AWS regions
  -l {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Set the logging output level
```
