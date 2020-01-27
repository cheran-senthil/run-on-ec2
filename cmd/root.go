package cmd

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/spf13/cobra"
)

var (
	regionImageIdMap = map[string]string{
		"eu-central-1": "ami-06e882db7f01fad97",
	}

	rootCmd = &cobra.Command{
		Use:   "run-on-ec2",
		Short: "CLI to quickly execute scripts on an AWS EC2 instance",
		Run: func(cmd *cobra.Command, args []string) {
			instanceType, _ := cmd.Flags().GetString("instance-type")
			region, _ := cmd.Flags().GetString("region")
			spot, _ := cmd.Flags().GetBool("spot")
			imageId := regionImageIdMap[region]

			sess, err := session.NewSession(&aws.Config{
				Region:      aws.String(region),
				Credentials: credentials.NewSharedCredentials("", "run-on-ec2"),
			})
			if err != nil {
				fmt.Println("Could not create session", err)
			}

			svc := ec2.New(sess)

			keyName := fmt.Sprintf("run-on-ec2-%s.pem", region)
			result, err := svc.CreateKeyPair(&ec2.CreateKeyPairInput{KeyName: aws.String(keyName)})
			if err != nil {
				fmt.Println("Could not create key pair", err)
			} else {
				fmt.Println("Saving key pair")
				keyFile, _ := os.Create(keyName)
				keyFile.WriteString(*result.KeyMaterial)
				keyFile.Sync()
				keyFile.Close()
			}

			if spot {
				requestResult, err := svc.RequestSpotInstances(&ec2.RequestSpotInstancesInput{
					LaunchSpecification: &ec2.RequestSpotLaunchSpecification{
						ImageId:      aws.String(imageId),
						InstanceType: aws.String(instanceType),
						KeyName:      aws.String(keyName),
					},
				})

				if err != nil {
					fmt.Println("Could not request spot instance", err)
					return
				}

				fmt.Println(requestResult)
			} else {
				runResult, err := svc.RunInstances(&ec2.RunInstancesInput{
					ImageId:      aws.String(imageId),
					InstanceType: aws.String(instanceType),
					MinCount:     aws.Int64(1),
					MaxCount:     aws.Int64(1),
					KeyName:      aws.String(keyName),
				})

				if err != nil {
					fmt.Println("Could not create instance", err)
					return
				}

				fmt.Println(runResult)
			}
		},
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringP("instance-type", "i", "t2.micro", "ec2 instance type")
	rootCmd.Flags().StringP("region", "r", "eu-central-1", "aws session region")
	rootCmd.Flags().BoolP("spot", "s", true, "request spot instances")
	rootCmd.Flags().IntP("volume", "v", 1, "volume attached in GiB")
}
