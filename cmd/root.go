package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hnakamur/go-scp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
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

	sshPort       = 22
	ipPermissions = []*ec2.IpPermission{
		(&ec2.IpPermission{}).
			SetIpProtocol("tcp").
			SetFromPort(int64(sshPort)).
			SetToPort(int64(sshPort)).
			SetIpRanges([]*ec2.IpRange{(&ec2.IpRange{}).SetCidrIp("0.0.0.0/0")}),
	}

	args    = 1
	rootCmd = &cobra.Command{
		Use:   "run-on-ec2 filename [flags]",
		Short: "CLI to quickly execute scripts on an AWS EC2 instance",
		Args:  cobra.ExactArgs(args),
		Run:   run,
	}
)

func init() {
	rootCmd.Flags().IntP("duration", "d", 10, "persistence time in minutes of ec2 instance after execution")
	rootCmd.Flags().BoolP("exec", "e", true, "execute the file")
	rootCmd.Flags().StringP("instance-type", "i", "t2.micro", "ec2 instance type")
	rootCmd.Flags().StringP("key-path", "k", "", "key path of valid aws key pair (defaults to creating a new key pair)")
	rootCmd.Flags().StringP("region", "r", "eu-central-1", "aws session region")
	rootCmd.Flags().BoolP("spot", "s", true, "request spot instances")
	rootCmd.Flags().BoolP("verbose", "v", false, "verbose logs (default false)")
	rootCmd.Flags().Int64P("volume", "m", 8, "volume attached in GiB")
}

func atexit(svc *ec2.EC2, instance *ec2.Instance, err error) {
	log.Debug("cleaning up")
	_, _ = svc.TerminateInstances(&ec2.TerminateInstancesInput{InstanceIds: []*string{instance.InstanceId}})
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(0)
}

func newEC2Client(region string) (*ec2.EC2, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials("", "run-on-ec2"),
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

	return []*ec2.BlockDeviceMapping{{
		DeviceName: describeRes.Images[0].RootDeviceName,
		Ebs:        &ec2.EbsBlockDevice{VolumeSize: aws.Int64(volume)},
	}}, nil
}

func getKeyPair(svc *ec2.EC2, keyPath string) (string, error) {
	keyName := strings.TrimSuffix(filepath.Base(keyPath), filepath.Ext(filepath.Base(keyPath)))
	result, err := svc.CreateKeyPair(&ec2.CreateKeyPairInput{KeyName: aws.String(keyName)})
	if err != nil {
		log.Debug("failed to create key pair, assuming key pair exists")
		return keyName, nil
	}

	log.Debug("created key pair")
	err = os.MkdirAll(filepath.Dir(keyPath), os.ModePerm)
	if err != nil {
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
		return nil, fmt.Errorf("unable to describe VPCs, %v", err)
	}

	var vpcID string
	for _, vpc := range result.Vpcs {
		if aws.BoolValue(vpc.IsDefault) {
			vpcID = aws.StringValue(vpc.VpcId)
		}
	}

	if vpcID == "" {
		return nil, errors.New("no default VPC found to associate security group with")
	}

	createRes, err := svc.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		GroupName:   aws.String("ssh"),
		Description: aws.String("ssh"),
		VpcId:       aws.String(vpcID),
	})
	if err != nil {
		return nil, err
	}

	_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupName:     aws.String("ssh"),
		IpPermissions: ipPermissions,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to set security group ssh ingress, %v", err)
	}

	return []*string{createRes.GroupId}, nil
}

func getSecurityGroup(svc *ec2.EC2) ([]*string, error) {
	result, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupNames: aws.StringSlice([]string{"ssh"}),
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

func getInstance(svc *ec2.EC2, instanceID string) (*ec2.Instance, error) {
	describeInstanceInp := &ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{instanceID}),
	}

	describeInstancesRes, err := svc.DescribeInstances(describeInstanceInp)
	if err != nil {
		return nil, err
	}

	for describeInstancesRes.Reservations[0].Instances[0].PublicIpAddress == nil {
		log.Debug("failed to get public IP address")
		describeInstancesRes, err = svc.DescribeInstances(describeInstanceInp)
		if err != nil {
			return nil, err
		}

		time.Sleep(time.Second)
	}

	return describeInstancesRes.Reservations[0].Instances[0], nil
}

func runInstance(svc *ec2.EC2, instanceType, keyPath, region string, spot bool, volume int64) (*ec2.Instance, error) {
	imageID := regionImageIDMap[region]
	blockDeviceMappings, err := getBlockDeviceMapping(svc, region, volume)
	if err != nil {
		return nil, fmt.Errorf("could not get block device mappings, %v", err)
	}

	log.Debug("got block device mappings")
	keyName, err := getKeyPair(svc, keyPath)
	if err != nil {
		return nil, err
	}

	log.Debug("got key pair")
	securityGroupIds, err := getSecurityGroup(svc)
	if err != nil {
		return nil, fmt.Errorf("could not get security group, %v", err)
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
		instanceCount := 1
		runRes, err := svc.RunInstances(&ec2.RunInstancesInput{
			BlockDeviceMappings: blockDeviceMappings,
			ImageId:             aws.String(imageID),
			InstanceType:        aws.String(instanceType),
			KeyName:             aws.String(keyName),
			MaxCount:            aws.Int64(int64(instanceCount)),
			MinCount:            aws.Int64(int64(instanceCount)),
			SecurityGroupIds:    securityGroupIds,
		})
		if err != nil {
			return nil, err
		}

		instanceID = aws.StringValue(runRes.Instances[0].InstanceId)
	}

	log.Debug("got instanceID")
	return getInstance(svc, instanceID)
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
	sshClientConfig := &ssh.ClientConfig{
		User:            "arch",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", publicIPAddress), sshClientConfig)
	for err != nil {
		log.Debug(err)
		client, err = ssh.Dial("tcp", fmt.Sprintf("%s:22", publicIPAddress), sshClientConfig)
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
		return scpClient.SendDir(filename, filepath.Base(filename), nil)
	}

	return scpClient.SendFile(filename, filepath.Base(filename))
}

func getCmd(filename string) (string, error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return "", err
	}

	filename = filepath.Base(filename)
	if fileInfo.IsDir() {
		return fmt.Sprintf("cd %s && chmod +x main.* && ./main.*", filename), nil
	}

	ext := filepath.Ext(filename)
	filenameWithoutExt := strings.TrimSuffix(filename, ext)
	switch ext {
	case ".c":
		return "gcc -g -static -std=gnu11 -lm -Wfatal-errors " +
			fmt.Sprintf("%s -o %s && ./%s", filename, filenameWithoutExt, filenameWithoutExt), nil
	case ".cpp":
		return "g++ -static -Wall -Wextra -Wno-unknown-pragmas -pedantic -std=c++17 -O2 -Wshadow -Wformat=2 " +
			"-Wfloat-equal -Wlogical-op -Wshift-overflow=2 -Wduplicated-cond -Wcast-qual -Wcast-align " +
			"-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC -D_FORTIFY_SOURCE=2 -fno-sanitize-recover -fstack-protector " +
			fmt.Sprintf("%s -o %s && ./%s", filename, filenameWithoutExt, filenameWithoutExt), nil
	case ".go":
		return fmt.Sprintf("go run %s", filename), nil
	default:
		return fmt.Sprintf("chmod +x %s && ./%s", filename, filename), nil
	}
}

func runCmd(client *ssh.Client, filename string) error {
	cmd, err := getCmd(filename)
	if err != nil {
		return err
	}

	fmt.Println(cmd)
	sess, err := client.NewSession()
	if err != nil {
		return err
	}

	defer sess.Close()

	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := sess.RequestPty("xterm", 40, 80, modes); err != nil {
		return err
	}

	if err := sess.Run(cmd); err != nil {
		return err
	}

	return nil
}

func run(cmd *cobra.Command, args []string) {
	filename := args[0]

	duration, _ := cmd.Flags().GetInt("duration")
	execute, _ := cmd.Flags().GetBool("exec")
	instanceType, _ := cmd.Flags().GetString("instance-type")
	keyPath, _ := cmd.Flags().GetString("key-path")
	region, _ := cmd.Flags().GetString("region")
	spot, _ := cmd.Flags().GetBool("spot")
	volume, _ := cmd.Flags().GetInt64("volume")
	if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
		log.SetLevel(log.DebugLevel)
	}

	if keyPath == "" {
		curr, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}

		keyPath = fmt.Sprintf("%s-%s.pem", region, curr.Username)
		log.Debugf("no key path provided, assuming ./%s", keyPath)
	}

	svc, err := newEC2Client(region)
	if err != nil {
		log.Fatal(err)
	}

	log.Debug("new EC2 client initialized, initializing instance...")
	instance, err := runInstance(svc, instanceType, keyPath, region, spot, volume)
	if err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGHUP,
	)

	go func() {
		<-c
		log.Error("interrupt caught")
		atexit(svc, instance, nil)
	}()

	log.Debug("new instance running, initializing SSH client...")
	sshClient, err := newSSHClient(keyPath, aws.StringValue(instance.PublicIpAddress))
	if err != nil {
		atexit(svc, instance, err)
	}

	defer sshClient.Close()
	log.Debug("new SSH client initialized, copying file...")
	if err = copyFile(sshClient, filename); err != nil {
		atexit(svc, instance, err)
	}

	if execute {
		log.Debug("copied file, executing command...")
		if err := runCmd(sshClient, filename); err != nil {
			log.Error(err)
		}

		log.Debug("execution complete, sleeping...")
	} else {
		log.Debug("copied file, sleeping...")
	}

	time.Sleep(time.Duration(duration) * time.Minute)
	if duration >= 0 {
		atexit(svc, instance, nil)
	}
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
