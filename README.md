# run-on-ec2
[![ReportCard][reportcard-image]][reportcard-url] [![GoDoc][godoc-image]][godoc-url] [![License][license-image]][license-url]

run-on-ec2 is a CLI to quickly execute scripts on an AWS EC2 instance.

## Prerequisites
1. Create an AWS IAM user, [here](https://console.aws.amazon.com/iam/home?#/users).

2. Install and configure [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html).

3. [Add a profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) with the name `run-on-ec2` to `~/.aws/config` (Linux & Mac) or `%USERPROFILE%\.aws\config` (Windows) 
```
[run-on-ec2]
aws_access_key_id = YOUR_IAM_KEY_ID
aws_secret_access_key = YOUR_IAM_SECRET_KEY
```

## Installation
```
$ go install
```

Alternatively, you can build the binary offline with,
```
$ go build -mod=vendor
```

## Help
```
$ run-on-ec2 -h
CLI to quickly execute scripts on an AWS EC2 instance

Usage:
  run-on-ec2 filename [flags]

Flags:
  -d, --duration int           persistence time in minutes, of ec2 instance after execution (default 10)
  -e, --exec                   execute the file (default true)
  -h, --help                   help for run-on-ec2
  -i, --instance-type string   ec2 instance type (default "t2.micro")
  -k, --key-path string        key path of a valid aws key pair (defaults to creating a new key pair)
  -r, --region string          aws session region (default "eu-central-1")
  -s, --spot                   request spot instances (default true)
  -v, --verbose                verbose logs (default false)
  -m, --volume int             volume attached in GiB (default 8)
```

## Apache License 2.0
  Copyright (c) 2020 Cheran Senthilkumar, Mukundan Senthilkumar

[reportcard-url]: https://goreportcard.com/report/github.com/cheran-senthil/run-on-ec2
[reportcard-image]: https://goreportcard.com/badge/github.com/cheran-senthil/run-on-ec2
[godoc-url]: https://godoc.org/github.com/cheran-senthil/run-on-ec2
[godoc-image]: https://godoc.org/github.com/cheran-senthil/run-on-ec2?status.svg
[license-url]: https://opensource.org/licenses/Apache-2.0
[license-image]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
