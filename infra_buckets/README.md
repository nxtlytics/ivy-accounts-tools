# Creates infrastructure s3 buckets per sysenv

## How to use it

<!-- markdownlint-disable MD013 -->

```shell
$ cd path/to/this/repo
$ AWS_PROFILE=profile-to-use poetry run python infra_buckets/infra_buckets.py --help
usage: infra_buckets.py [-h] -c PHASE -p PURPOSE [-t TAG_PREFIX] [-r REGIONS] [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG}]

Creates infrastructure s3 buckets per sysenv

options:
  -h, --help            show this help message and exit
  -c PHASE, --phase PHASE
                        AWS Sub Account Phase (prod, dev, stage, ...)
  -p PURPOSE, --purpose PURPOSE
                        AWS Sub Account purpose (app, tools, sandbox, ...)
  -t TAG_PREFIX, --tag-prefix TAG_PREFIX
                        Tag prefix also known as namespace
  -r REGIONS, --regions REGIONS
                        Comma-separated list of AWS regions
  -l {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Set the logging output level
```
