package cmd

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "run-on-ec2",
	Short: "CLI to quickly execute scripts on an AWS EC2 instance",
	Run: func(cmd *cobra.Command, args []string) {
		instanceType, _ := cmd.Flags().GetString("instance-type")
		region, _ := cmd.Flags().GetString("region")
		isSpot, _ := cmd.Flags().GetBool("spot")

		sess, err := session.NewSession(&aws.Config{
			Region:      aws.String(region),
			Credentials: credentials.NewSharedCredentials("", "private"),
		})
		if err != nil {
			fmt.Println("Could not create session", err)
		}

		svc := ec2.New(sess)

		if isSpot {
			runResult, err := svc.RequestSpotInstances(&ec2.RequestSpotInstancesInput{
				LaunchSpecification: &ec2.RequestSpotLaunchSpecification{
					ImageId:      aws.String("ami-06e882db7f01fad97"),
					InstanceType: aws.String(instanceType),
					SecurityGroupIds: []*string{
						aws.String("sg-5ee7a43a"),
					},
				},
			})

			if err != nil {
				fmt.Println("Could not request spot instance", err)
				return
			}

			fmt.Println(runResult)
		} else {
			runResult, err := svc.RunInstances(&ec2.RunInstancesInput{
				ImageId:      aws.String("ami-06e882db7f01fad97"),
				InstanceType: aws.String("t2.micro"),
				MinCount:     aws.Int64(1),
				MaxCount:     aws.Int64(1),
			})

			if err != nil {
				fmt.Println("Could not create instance", err)
				return
			}

			fmt.Println(runResult)
		}
	},
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringP("instance-type", "i", "t2.micro", "ec2 instance type")
	rootCmd.Flags().StringP("region", "r", "eu-central-1", "aws session region")
	rootCmd.Flags().BoolP("spot", "s", true, "use spot instances")
}
