package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/spf13/cobra"
)

var (
	regionImageIDMap = map[string]string{
		"eu-central-1": "ami-06e882db7f01fad97",
	}

	rootCmd = &cobra.Command{
		Use:   "run-on-ec2",
		Short: "CLI to quickly execute scripts on an AWS EC2 instance",
		Run: func(cmd *cobra.Command, args []string) {
			region, _ := cmd.Flags().GetString("region")
			spot, _ := cmd.Flags().GetBool("spot")
			instanceType, _ := cmd.Flags().GetString("instance")
			volume, _ := cmd.Flags().GetInt64("volume")
			imageID := regionImageIDMap[region]

			sess, err := session.NewSession(&aws.Config{
				Region:      aws.String(region),
				Credentials: credentials.NewSharedCredentials("", "run-on-ec2"),
			})
			if err != nil {
				fmt.Println("Could not create session", err)
				return
			}

			svc := ec2.New(sess)
			keyName, err := createKeyPair(svc, region)
			if err != nil {
				fmt.Println("Could not create key pair", err)
				return
			}

			if spot {
				fmt.Println(runSpotInstance(svc, imageID, instanceType, keyName, volume))
			} else {
				fmt.Println(runInstance(svc, imageID, instanceType, keyName, volume))
			}
		},
	}
)

func createKeyPair(svc *ec2.EC2, region string) (string, error) {
	keyName := fmt.Sprintf("run-on-ec2-%s", region)
	result, err := svc.CreateKeyPair(&ec2.CreateKeyPairInput{KeyName: aws.String(keyName)})
	if err != nil {
		return keyName, nil
	}

	pemFile, err := os.Create(fmt.Sprintf("%s.pem", keyName))
	if err != nil {
		return "", err
	}

	pemFile.WriteString(*result.KeyMaterial)
	pemFile.Sync()
	pemFile.Close()
	return keyName, nil
}

func volumeToBlockDeviceMappings(volume int64) []*ec2.BlockDeviceMapping {
	return []*(ec2.BlockDeviceMapping){&ec2.BlockDeviceMapping{
		DeviceName: aws.String("/dev/xvda"),
		Ebs: &ec2.EbsBlockDevice{
			DeleteOnTermination: aws.Bool(true),
			Encrypted:           aws.Bool(false),
			VolumeSize:          aws.Int64(volume),
			VolumeType:          aws.String("gp2"),
		},
	}}
}

func runSpotInstance(svc *ec2.EC2, imageID, instanceType, keyName string, volume int64) (*ec2.Instance, error) {
	requestResult, err := svc.RequestSpotInstances(&ec2.RequestSpotInstancesInput{
		LaunchSpecification: &ec2.RequestSpotLaunchSpecification{
			ImageId:             aws.String(imageID),
			InstanceType:        aws.String(instanceType),
			KeyName:             aws.String(keyName),
			BlockDeviceMappings: volumeToBlockDeviceMappings(volume),
		},
	})
	if err != nil {
		return nil, err
	}

	describeSIRInput := &ec2.DescribeSpotInstanceRequestsInput{
		SpotInstanceRequestIds: []*string{requestResult.SpotInstanceRequests[0].SpotInstanceRequestId},
	}

	describeSIROutput, err := svc.DescribeSpotInstanceRequests(describeSIRInput)
	for err != nil || len(describeSIROutput.SpotInstanceRequests) == 0 || describeSIROutput.SpotInstanceRequests[0].InstanceId == nil {
		describeSIROutput, err = svc.DescribeSpotInstanceRequests(describeSIRInput)
		time.Sleep(time.Second)
	}

	ec2Description, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{describeSIROutput.SpotInstanceRequests[0].InstanceId},
	})
	if err != nil {
		return nil, err
	}

	return ec2Description.Reservations[0].Instances[0], nil
}

func runInstance(svc *ec2.EC2, imageID, instanceType, keyName string, volume int64) (*ec2.Instance, error) {
	runResult, err := svc.RunInstances(&ec2.RunInstancesInput{
		ImageId:             aws.String(imageID),
		InstanceType:        aws.String(instanceType),
		MinCount:            aws.Int64(1),
		MaxCount:            aws.Int64(1),
		KeyName:             aws.String(keyName),
		BlockDeviceMappings: volumeToBlockDeviceMappings(volume),
	})
	if err != nil {
		return nil, err
	}

	ec2Description, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{runResult.Instances[0].InstanceId},
	})

	return ec2Description.Reservations[0].Instances[0], nil
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringP("input", "i", "input.txt", "input file/folder name")
	rootCmd.Flags().StringP("region", "r", "eu-central-1", "aws session region")
	rootCmd.Flags().BoolP("spot", "s", true, "request spot instances")
	rootCmd.Flags().StringP("instance", "t", "t2.micro", "ec2 instance type")
	rootCmd.Flags().Int64P("volume", "v", 4, "volume attached in GiB")
}
