package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hnakamur/go-scp"
	log "github.com/sirupsen/logrus"
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
		Use:   fmt.Sprintf("%s filename", name),
		Short: "CLI to quickly execute scripts on an AWS EC2 instance",
		Args:  cobra.ExactArgs(1),
		Run:   run,
	}
)

func init() {
	rootCmd.Flags().IntP("duration", "d", 10, "persistence time in minutes, of ec2 instance after execution")
	rootCmd.Flags().StringP("instance-type", "i", "t2.micro", "ec2 instance type")
	rootCmd.Flags().StringP("key-path", "k", "", "key path of a valid aws key pair (defaults to creating a new key pair)")
	rootCmd.Flags().StringP("region", "r", "eu-central-1", "aws session region")
	rootCmd.Flags().BoolP("spot", "s", true, "request spot instances")
	rootCmd.Flags().BoolP("verbose", "v", false, "verbose logs (default false)")
	rootCmd.Flags().Int64P("volume", "m", 8, "volume attached in GiB")
}

func atexit(svc *ec2.EC2, duration int, instance *ec2.Instance) {
	if duration < 0 {
		log.Warn("instance will persist")
		return
	}

	log.Info("cleaning up")
	_, err := svc.TerminateInstances(&ec2.TerminateInstancesInput{InstanceIds: []*string{instance.InstanceId}})
	if err != nil {
		panic(err)
	}
}

func newEC2Client(region string) (*ec2.EC2, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials("", name),
	})
	if err != nil {
		return nil, err
	}

	log.Debug("new AWS session initialized")
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
		Ebs:        &ec2.EbsBlockDevice{VolumeSize: aws.Int64(volume)},
	}}, nil
}

func getKeyPair(svc *ec2.EC2, keyPath, region string) (string, error) {
	keyName := strings.TrimSuffix(filepath.Base(keyPath), filepath.Ext(filepath.Base(keyPath)))
	result, err := svc.CreateKeyPair(&ec2.CreateKeyPairInput{KeyName: aws.String(keyName)})
	if err != nil {
		log.Warn("failed to create key pair, assuming key pair exists")
		return keyName, nil
	}

	log.Debug("created key pair")
	if err := os.MkdirAll(filepath.Dir(keyPath), os.ModePerm); err != nil {
		return "", err
	}

	pemFile, err := os.Create(keyPath)
	if err != nil {
		return "", err
	}

	log.Debug("created pem file")
	defer pemFile.Close()
	_, err = pemFile.WriteString(*result.KeyMaterial)
	if err != nil {
		return "", err
	}

	if err := pemFile.Sync(); err != nil {
		return "", err
	}

	log.Debug("saved key material to pem file")
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
		log.Debug(err)
		return createSecurityGroup(svc)
	}

	return []*string{result.SecurityGroups[0].GroupId}, nil
}

func getSpotInstanceID(svc *ec2.EC2, requestResult *ec2.RequestSpotInstancesOutput) string {
	spotInstanceRequest := &ec2.DescribeSpotInstanceRequestsInput{
		SpotInstanceRequestIds: []*string{requestResult.SpotInstanceRequests[0].SpotInstanceRequestId},
	}

	describeRes, err := svc.DescribeSpotInstanceRequests(spotInstanceRequest)
	for err != nil ||
		len(describeRes.SpotInstanceRequests) == 0 ||
		describeRes.SpotInstanceRequests[0].InstanceId == nil {
		log.Debug("failed to describe spot instance")
		describeRes, err = svc.DescribeSpotInstanceRequests(spotInstanceRequest)
		time.Sleep(time.Second)
	}

	return aws.StringValue(describeRes.SpotInstanceRequests[0].InstanceId)
}

func runInstance(svc *ec2.EC2, instanceType, keyPath, region string, spot bool, volume int64) (*ec2.Instance, error) {
	imageID := regionImageIDMap[region]
	blockDeviceMappings, err := getBlockDeviceMapping(svc, region, volume)
	if err != nil {
		return nil, fmt.Errorf("Could not get block device mappings, %v", err)
	}

	log.Debug("got block device mappings")
	keyName, err := getKeyPair(svc, keyPath, region)
	if err != nil {
		log.Error(err)
	}

	log.Debug("got key pair")
	securityGroupIds, err := getSecurityGroup(svc)
	if err != nil {
		return nil, fmt.Errorf("Could not get security group, %v", err)
	}

	log.Debug("got security group")
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

		log.Debug("requested spot instance")
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

	log.Debug("got instanceID")
	describeInstancesRes, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{instanceID}),
	})
	if err != nil {
		return nil, err
	}

	return describeInstancesRes.Reservations[0].Instances[0], nil
}

func pemFileToSigner(keyPath string) (ssh.Signer, error) {
	pemBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	log.Debug("parsed permission file")
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func newSSHClient(keyPath, publicIPAddress string) (*ssh.Client, error) {
	signer, err := pemFileToSigner(keyPath)
	if err != nil {
		return nil, err
	}

	log.Debug("got signer")
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", publicIPAddress), &ssh.ClientConfig{
		User:            "arch",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	for err != nil {
		log.Debug(err)
		client, err = ssh.Dial("tcp", fmt.Sprintf("%s:22", publicIPAddress), &ssh.ClientConfig{
			User:            "arch",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		})
		time.Sleep(time.Second)
	}

	return client, err
}

func copyFile(sshClient *ssh.Client, filename string) error {
	scpClient := scp.NewSCP(sshClient)
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return err
	}

	if fileInfo.IsDir() {
		return scpClient.SendDir(filename, filename, nil)
	}

	return scpClient.SendFile(filename, filename)
}

func runCmd(client *ssh.Client, runCmd string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}

	defer sess.Close()
	log.Debug("new SSH session initialized")
	stdoutPipe, err := sess.StdoutPipe()
	if err != nil {
		return err
	}

	log.Debug("new stdout pipe initialized")
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		return err
	}

	log.Debug("new stderr pipe initialized")
	if err := sess.Start(runCmd); err != nil {
		return err
	}

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

	if err := sess.Wait(); err != nil {
		return err
	}

	quit <- true
	io.Copy(os.Stdout, stdoutPipe)
	io.Copy(os.Stderr, stderrPipe)
	return nil
}

func run(cmd *cobra.Command, args []string) {
	filename := args[0]

	duration, _ := cmd.Flags().GetInt("duration")
	instanceType, _ := cmd.Flags().GetString("instance-type")
	keyPath, _ := cmd.Flags().GetString("key-path")
	region, _ := cmd.Flags().GetString("region")
	spot, _ := cmd.Flags().GetBool("spot")
	volume, _ := cmd.Flags().GetInt64("volume")
	if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
		log.SetLevel(log.DebugLevel)
	}

	if keyPath == "" {
		user, err := user.Current()
		if err != nil {
			log.Error(err)
			return
		}

		keyPath = fmt.Sprintf("%s-%s-%s.pem", name, region, user.Username)
		log.Warnf("no key path provided, assuming ./%s", keyPath)
	}

	svc, err := newEC2Client(region)
	if err != nil {
		log.Error(err)
		return
	}

	log.Info("new EC2 client initialized, initializing instance...")
	instance, err := runInstance(svc, instanceType, keyPath, region, spot, volume)
	if err != nil {
		log.Error(err)
		return
	}

	defer atexit(svc, duration, instance)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGHUP,
	)

	go func() {
		<-c
		atexit(svc, duration, instance)
		os.Exit(1)
	}()

	log.Info("new instance running, initializing SSH client...")
	sshClient, err := newSSHClient(keyPath, aws.StringValue(instance.PublicIpAddress))
	if err != nil {
		log.Error(err)
		return
	}

	defer sshClient.Close()
	log.Info("new SSH client initialized, copying file...")
	if err = copyFile(sshClient, filename); err != nil {
		log.Error(err)
		return
	}

	log.Info("copied file, executing command...")
	if err := runCmd(sshClient, fmt.Sprintf("echo \"successfully copied %s\"", filename)); err != nil {
		log.Error(err)
	}

	log.Info("execution complete, sleeping...")
	time.Sleep(time.Duration(duration) * time.Minute)
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
