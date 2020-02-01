# run-on-ec2
[![ReportCard][reportcard-image]][reportcard-url] [![GoDoc][godoc-image]][godoc-url] [![License][license-image]][license-url]

run-on-ec2 is a CLI to quickly execute scripts on an AWS EC2 instance.

# Prerequisites

Create an AWS IAM user, [here](https://console.aws.amazon.com/iam/home?#/users).

Install and configure [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html).

[Add a profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) with the name `run-on-ec2` to `~/.aws/config` (Linux & Mac) or `%USERPROFILE%\.aws\config` (Windows) 
```
[run-on-ec2]
aws_access_key_id = YOUR_IAM_KEY_ID
aws_secret_access_key = YOUR_IAM_SECRET_KEY
```

# Installation
```
$ go install
```

# Usage
```
$ run-on-ec2 filename
```


# Apache License 2.0

  Copyright (c) 2019 Cheran Senthilkumar, Mukundan Senthilkumar

[reportcard-url]: https://goreportcard.com/report/github.com/cheran-senthil/run-on-ec2
[reportcard-image]: https://goreportcard.com/badge/github.com/cheran-senthil/run-on-ec2
[godoc-url]: https://godoc.org/github.com/cheran-senthil/run-on-ec2
[godoc-image]: https://godoc.org/github.com/cheran-senthil/run-on-ec2?status.svg
[license-url]: https://opensource.org/licenses/Apache-2.0
[license-image]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
