package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	name = "run-on-ec2"

	regionImageIDMap = map[string]string{
		"us-east-1":      "ami-0f040c7d22aedeb27",
		"us-east-2":      "ami-0470431e11a734fd9",
		"us-west-1":      "ami-05cdd0c340f2889fe",
		"us-west-2":      "ami-0b6363764d2a80871",
		"ca-central-1":   "ami-01b3269d70a1de16c",
		"eu-central-1":   "ami-06e882db7f01fad97",
		"eu-north-1":     "ami-02ae88ed88290671a",
		"eu-west-1":      "ami-08613bbdd5117c26e",
		"eu-west-2":      "ami-020f8e712266ac616",
		"eu-west-3":      "ami-01360f4ce2b7cc8df",
		"ap-east-1":      "ami-17b3f666",
		"ap-northeast-1": "ami-0830b6d0901519dfb",
		"ap-northeast-2": "ami-0e479608b3609ee19",
		"ap-south-1":     "ami-0280b0286f256a533",
		"ap-southeast-1": "ami-0ebc029a114aa199e",
		"ap-southeast-2": "ami-01fdf683a88ff498e",
		"sa-east-1":      "ami-07183794882825eb4",
		"me-south-1":     "ami-054bbb7ef03ab6c36",
	}

	ipPermissions = []*ec2.IpPermission{
		(&ec2.IpPermission{}).
			SetIpProtocol("tcp").
			SetFromPort(22).
			SetToPort(22).
			SetIpRanges([]*ec2.IpRange{(&ec2.IpRange{}).SetCidrIp("0.0.0.0/0")}),
	}

	rootCmd = &cobra.Command{
		Use:   name,
		Short: "CLI to quickly execute scripts on an AWS EC2 instance",
		Args:  cobra.ExactArgs(1),
		Run:   run,
	}
)

func init() {
	rootCmd.Flags().IntP("duration", "d", 10, "duration time of ec2 instance (minutes)")
	rootCmd.Flags().StringP("instance", "i", "t2.micro", "ec2 instance type")
	rootCmd.Flags().StringP("region", "r", "eu-central-1", "aws session region")
	rootCmd.Flags().BoolP("spot", "s", true, "request spot instances")
	rootCmd.Flags().Int64P("volume", "v", 8, "volume attached in GiB")
}

func atexit(svc *ec2.EC2, duration int, instanceIds []*string) error {
	fmt.Printf("--- atexit triggered, terminating instances in %d minutes ---", duration)
	time.Sleep(time.Duration(duration) * time.Minute)
	input := &ec2.TerminateInstancesInput{
		InstanceIds: instanceIds,
		DryRun:      aws.Bool(false),
	}

	_, err := svc.TerminateInstances(input)
	if err != nil {
		return err
	}

	return nil
}

func getFlags(cmd *cobra.Command) (int, string, string, bool, int64, error) {
	duration, err := cmd.Flags().GetInt("duration")
	if err != nil {
		return 0, "", "", false, 0, err
	}
	instanceType, err := cmd.Flags().GetString("instance")
	if err != nil {
		return 0, "", "", false, 0, err
	}
	region, err := cmd.Flags().GetString("region")
	if err != nil {
		return 0, "", "", false, 0, err
	}
	spot, err := cmd.Flags().GetBool("spot")
	if err != nil {
		return 0, "", "", false, 0, err
	}
	volume, err := cmd.Flags().GetInt64("volume")
	if err != nil {
		return 0, "", "", false, 0, err
	}

	return duration, instanceType, region, spot, volume, nil
}

func newEC2Client(region string) (*ec2.EC2, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials("", name),
	})
	if err != nil {
		return nil, err
	}

	return ec2.New(sess), nil
}

func getBlockDeviceMapping(svc *ec2.EC2, region string, volume int64) ([]*ec2.BlockDeviceMapping, error) {
	describeRes, err := svc.DescribeImages(&ec2.DescribeImagesInput{
		ImageIds: aws.StringSlice([]string{regionImageIDMap[region]}),
	})
	if err != nil {
		return nil, err
	}

	return []*(ec2.BlockDeviceMapping){&ec2.BlockDeviceMapping{
		DeviceName: describeRes.Images[0].RootDeviceName,
		Ebs: &ec2.EbsBlockDevice{
			DeleteOnTermination: aws.Bool(true),
			Encrypted:           aws.Bool(false),
			VolumeSize:          aws.Int64(volume),
			VolumeType:          aws.String("gp2"),
		},
	}}, nil
}

func getKeyPair(svc *ec2.EC2, region string) (string, error) {
	keyName := fmt.Sprintf("%s-%s", name, region)
	result, err := svc.CreateKeyPair(&ec2.CreateKeyPairInput{KeyName: aws.String(keyName)})
	if err != nil {
		return keyName, nil
	}

	pemFile, err := os.Create(fmt.Sprintf("%s.pem", keyName))
	if err != nil {
		return "", err
	}

	defer pemFile.Close()
	pemFile.WriteString(*result.KeyMaterial)
	pemFile.Sync()

	return keyName, nil
}

func createSecurityGroup(svc *ec2.EC2) ([]*string, error) {
	result, err := svc.DescribeVpcs(nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to describe VPCs, %v", err)
	}

	var vpcID string
	for _, vpc := range result.Vpcs {
		if aws.BoolValue(vpc.IsDefault) {
			vpcID = aws.StringValue(vpc.VpcId)
		}
	}

	if vpcID == "" {
		return nil, errors.New("No default VPC found to associate security group with")
	}

	createRes, err := svc.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(name),
		Description: aws.String(name),
		VpcId:       aws.String(vpcID),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidVpcID.NotFound":
				return nil, fmt.Errorf("Unable to find VPC with ID %s", vpcID)
			case "InvalidGroup.Duplicate":
				return nil, fmt.Errorf("Security group %s already exists", name)
			}
		}
		return nil, fmt.Errorf("Unable to create security group %s, %v", name, err)
	}

	_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupName:     aws.String(name),
		IpPermissions: ipPermissions,
	})
	if err != nil {
		return nil, fmt.Errorf("Unable to set security group %s ingress, %v", name, err)
	}

	return []*string{createRes.GroupId}, nil
}

func getSecurityGroup(svc *ec2.EC2) ([]*string, error) {
	result, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupNames: aws.StringSlice([]string{name}),
	})
	if err != nil {
		return createSecurityGroup(svc)
	}

	return []*string{result.SecurityGroups[0].GroupId}, nil
}

func getSpotInstanceID(svc *ec2.EC2, requestResult *ec2.RequestSpotInstancesOutput) string {
	spotInstanceRequest := &ec2.DescribeSpotInstanceRequestsInput{
		SpotInstanceRequestIds: []*string{requestResult.SpotInstanceRequests[0].SpotInstanceRequestId},
	}

	describeRes, err := svc.DescribeSpotInstanceRequests(spotInstanceRequest)
	for err != nil || len(describeRes.SpotInstanceRequests) == 0 || describeRes.SpotInstanceRequests[0].InstanceId == nil {
		describeRes, err = svc.DescribeSpotInstanceRequests(spotInstanceRequest)
		time.Sleep(time.Second)
	}

	return aws.StringValue(describeRes.SpotInstanceRequests[0].InstanceId)
}

func runInstance(svc *ec2.EC2, spot bool, instanceType, region string, volume int64) (*ec2.Instance, error) {
	imageID := regionImageIDMap[region]
	blockDeviceMappings, err := getBlockDeviceMapping(svc, region, volume)
	if err != nil {
		return nil, fmt.Errorf("Could not get block device mappings, %v", err)
	}

	keyName, err := getKeyPair(svc, region)
	if err != nil {
		return nil, fmt.Errorf("Could not get key pair, %v", err)
	}

	securityGroupIds, err := getSecurityGroup(svc)
	if err != nil {
		return nil, fmt.Errorf("Could not get security group, %v", err)
	}

	var instanceID string
	if spot {
		requestRes, err := svc.RequestSpotInstances(&ec2.RequestSpotInstancesInput{
			LaunchSpecification: &ec2.RequestSpotLaunchSpecification{
				BlockDeviceMappings: blockDeviceMappings,
				ImageId:             aws.String(imageID),
				InstanceType:        aws.String(instanceType),
				KeyName:             aws.String(keyName),
				SecurityGroupIds:    securityGroupIds,
			},
		})
		if err != nil {
			return nil, err
		}

		instanceID = getSpotInstanceID(svc, requestRes)
	} else {
		runRes, err := svc.RunInstances(&ec2.RunInstancesInput{
			BlockDeviceMappings: blockDeviceMappings,
			ImageId:             aws.String(imageID),
			InstanceType:        aws.String(instanceType),
			MinCount:            aws.Int64(1),
			MaxCount:            aws.Int64(1),
			KeyName:             aws.String(keyName),
			SecurityGroupIds:    securityGroupIds,
		})
		if err != nil {
			return nil, err
		}

		instanceID = aws.StringValue(runRes.Instances[0].InstanceId)
	}

	describeInstancesRes, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{instanceID}),
	})
	if err != nil {
		return nil, err
	}

	return describeInstancesRes.Reservations[0].Instances[0], nil
}

func pemFileToSigner(pemFile string) (ssh.Signer, error) {
	pemBytes, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func newSSHClient(region, publicIPAddress string) (*ssh.Client, error) {
	signer, err := pemFileToSigner(fmt.Sprintf("%s-%s.pem", name, region))
	if err != nil {
		return nil, err
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", publicIPAddress), &ssh.ClientConfig{
		User:            "arch",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	for err != nil {
		client, err = ssh.Dial("tcp", fmt.Sprintf("%s:22", publicIPAddress), &ssh.ClientConfig{
			User:            "arch",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		})
		time.Sleep(time.Second)
	}

	return client, err
}

func copyFile(client *ssh.Client, file string) error {
	fileInfo, err := os.Stat(file)
	if err != nil {
		return err
	}

	if fileInfo.IsDir() {
		return filepath.Walk(
			name,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}

				// copy file here
				return nil
			},
		)
	} else {
		// copy file here
	}

	return nil
}

func runCmd(client *ssh.Client, runCmd string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}

	stdoutPipe, err := sess.StdoutPipe()
	if err != nil {
		return err
	}

	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		return err
	}

	sess.Start(runCmd)
	quit := make(chan bool)
	go func() {
		for {
			select {
			case <-quit:
				return
			default:
				io.Copy(os.Stdout, stdoutPipe)
				io.Copy(os.Stderr, stderrPipe)
			}
		}
	}()

	sess.Wait()
	quit <- true

	io.Copy(os.Stdout, stdoutPipe)
	io.Copy(os.Stderr, stderrPipe)
	return nil
}

func exec(region, publicIPAddress, file string) error {
	client, err := newSSHClient(region, publicIPAddress)
	if err != nil {
		return err
	}

	err = copyFile(client, file)
	if err != nil {
		return err
	}

	return runCmd(client, "echo 'testing' && sleep 3 && echo 'test'")
	// return runCmd(client, fmt.Sprintf("run %s", file))
}

func run(cmd *cobra.Command, args []string) {
	duration, instanceType, region, spot, volume, err := getFlags(cmd)
	if err != nil {
		fmt.Println(err)
		return
	}

	svc, err := newEC2Client(region)
	instance, err := runInstance(svc, spot, instanceType, region, volume)
	instanceIds := []*string{instance.InstanceId}
	defer atexit(svc, duration, instanceIds)
	if err := exec(region, aws.StringValue(instance.PublicIpAddress), args[0]); err != nil {
		fmt.Println(err)
		return
	}
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
