# amazon-ec2-update-ami
Automatically update the AMI using AWS Systems Manager's Automation Document

## Shared document information provided by AWS (2021/2/5)


> aws ssm list-documents --no-cli-pager --output table --filters "Key=Owner,Values=Amazon" "Key=DocumentType,Values=Automation" --query 'DocumentIdentifiers[*].{DocumentName:Name, DocumentType:DocumentType,Platform1:PlatformTypes[0],Platform2:PlatformTypes[1],Platform3:PlatformTypes[2],Format:DocumentFormat,TargetType:TargetType,DocVer:DocumentVersion,Schema:SchemaVersion}'

> aws ssm list-documents --no-cli-pager --output table --filters "Key=Owner,Values=Amazon" "Key=DocumentType,Values=Command" --query 'DocumentIdentifiers[*].{DocumentName:Name, DocumentType:DocumentType,Platform1:PlatformTypes[0],Platform2:PlatformTypes[1],Platform3:PlatformTypes[2],Format:DocumentFormat,TargetType:TargetType,DocVer:DocumentVersion,Schema:SchemaVersion}'

> aws ssm list-documents --no-cli-pager --output table --filters "Key=Owner,Values=Amazon" "Key=DocumentType,Values=Session" --query 'DocumentIdentifiers[*].{DocumentName:Name, DocumentType:DocumentType,Platform1:PlatformTypes[0],Platform2:PlatformTypes[1],Platform3:PlatformTypes[2],Format:DocumentFormat,TargetType:TargetType,DocVer:DocumentVersion,Schema:SchemaVersion}'

> aws ssm list-documents --no-cli-pager --output table --filters "Key=Owner,Values=Amazon" "Key=DocumentType,Values=Package" --query 'DocumentIdentifiers[*].{DocumentName:Name, DocumentType:DocumentType,Platform1:PlatformTypes[0],Platform2:PlatformTypes[1],Platform3:PlatformTypes[2],Format:DocumentFormat,TargetType:TargetType,DocVer:DocumentVersion,Schema:SchemaVersion}'

> aws ssm list-documents --no-cli-pager --output table --filters "Key=Owner,Values=ThirdParty" "Key=DocumentType,Values=Package" --query 'DocumentIdentifiers[*].{DocumentName:Name, DocumentType:DocumentType,Platform1:PlatformTypes[0],Platform2:PlatformTypes[1],Platform3:PlatformTypes[2],Format:DocumentFormat,TargetType:TargetType,DocVer:DocumentVersion,Schema:SchemaVersion}'


### List-Documents (Automation)

```

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
|                                                                                               ListDocuments                                                                                               |
+--------+------------------------------------------------------------------------+---------------+---------+------------+------------+------------+---------+----------------------------------------------+
| DocVer |                             DocumentName                               | DocumentType  | Format  | Platform1  | Platform2  | Platform3  | Schema  |                 TargetType                   |
+--------+------------------------------------------------------------------------+---------------+---------+------------+------------+------------+---------+----------------------------------------------+
|  1     |  AWS-ASGEnterStandby                                                   |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Volume                           |
|  1     |  AWS-ASGExitStandby                                                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Volume                           |
|  1     |  AWS-AttachEBSVolume                                                   |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-AttachIAMToInstance                                               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-ChangeDDBRWCapacityMode                                           |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-ConfigureCloudTrailLogging                                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-ConfigureCloudWatchOnEC2Instance                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-ConfigureS3BucketLogging                                          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::S3::Bucket                            |
|  1     |  AWS-ConfigureS3BucketVersioning                                       |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::S3::Bucket                            |
|  1     |  AWS-CopySnapshot                                                      |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Snapshot                         |
|  1     |  AWS-CreateDynamoDbBackup                                              |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-CreateImage                                                       |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-CreateJiraIssue                                                   |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-CreateManagedLinuxInstance                                        |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-CreateManagedLinuxInstanceWithApproval                            |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-CreateManagedWindowsInstance                                      |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-CreateManagedWindowsInstanceWithApproval                          |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-CreateRdsSnapshot                                                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWS-CreateServiceNowIncident                                          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-CreateSnapshot                                                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Volume                           |
|  1     |  AWS-DeleteCloudFormationStack                                         |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudFormation::Stack                 |
|  1     |  AWS-DeleteCloudFormationStackWithApproval                             |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudFormation::Stack                 |
|  1     |  AWS-DeleteDynamoDbBackup                                              |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-DeleteDynamoDbTableBackups                                        |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-DeleteEKSCluster                                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-DeleteEbsVolumeSnapshots                                          |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Volume                           |
|  1     |  AWS-DeleteIAMInlinePolicy                                             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-DeleteImage                                                       |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-DeleteSnapshot                                                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Snapshot                         |
|  1     |  AWS-DetachEBSVolume                                                   |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Volume                           |
|  1     |  AWS-DisableIncomingSSHOnPort22                                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-DisablePublicAccessForSecurityGroup                               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::SecurityGroup                    |
|  1     |  AWS-DisableS3BucketPublicReadWrite                                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::S3::Bucket                            |
|  1     |  AWS-EnableCLBAccessLogs                                               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-EnableCloudTrail                                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-EnableExplorer                                                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-EnableS3BucketEncryption                                          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::S3::Bucket                            |
|  1     |  AWS-ExportOpsDataToS3                                                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-ExportPatchReportToS3                                             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-HelloWorld                                                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-InstallAmazonECSAgent                                             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-PatchAsgInstance                                                  |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-PatchInstanceWithRollback                                         |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-PublishSNSNotification                                            |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::SNS::Topic                            |
|  1     |  AWS-RebootRdsInstance                                                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWS-ReleaseElasticIP                                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::EIP                              |
|  1     |  AWS-ResizeInstance                                                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-RestartEC2Instance                                                |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-RestartEC2InstanceWithApproval                                    |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-RunCfnLint                                                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-RunPacker                                                         |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-SetupInventory                                                    |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-SetupManagedInstance                                              |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-SetupManagedRoleOnEc2Instance                                     |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-StartEC2Instance                                                  |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-StartEC2InstanceWithApproval                                      |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-StartRdsInstance                                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWS-StartStopAuroraCluster                                            |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-StopEC2Instance                                                   |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-StopEC2InstanceWithApproval                                       |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-StopRdsInstance                                                   |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWS-TerminateEC2Instance                                              |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-TerminateEC2InstanceWithApproval                                  |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWS-UpdateAmazonECSAgent                                              |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-UpdateCloudFormationStack                                         |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudFormation::Stack                 |
|  1     |  AWS-UpdateCloudFormationStackWithApproval                             |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudFormation::Stack                 |
|  1     |  AWS-UpdateEKSManagedNodegroupVersion                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-UpdateLinuxAmi                                                    |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWS-UpdateWindowsAmi                                                  |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  6     |  AWSSupport-ActivateWindowsWithAmazonLicense                           |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSSupport-CheckAndMountEFS                                           |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWSSupport-CollectEKSInstanceLogs                                     |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSSupport-ConnectivityTroubleshooter                                 |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  13    |  AWSSupport-ExecuteEC2Rescue                                           |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  5     |  AWSSupport-GrantPermissionsToIAMUser                                  |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  4     |  AWSSupport-ListEC2Resources                                           |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSSupport-ManageRDPSettings                                          |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  4     |  AWSSupport-ManageWindowsService                                       |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSSupport-MigrateEC2ClassicToVPC                                     |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWSSupport-RecoverWorkSpace                                           |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWSSupport-RecoverWorkSpaceWithApproval                               |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  10    |  AWSSupport-ResetAccess                                                |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  5     |  AWSSupport-SendLogBundleToS3Bucket                                    |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWSSupport-SetupConfig                                                |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSSupport-SetupIPMonitoringFromVPC                                   |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSSupport-ShareRDSSnapshot                                           |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  12    |  AWSSupport-StartEC2RescueWorkflow                                     |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSSupport-TerminateIPMonitoringFromVPC                               |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWSSupport-TroubleshootConnectivityToRDS                              |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWSSupport-TroubleshootDirectoryTrust                                 |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  3     |  AWSSupport-TroubleshootRDP                                            |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  4     |  AWSSupport-TroubleshootS3PublicRead                                   |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSSupport-TroubleshootSSH                                            |  Automation   |  JSON   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  6     |  AWSSupport-UpgradeWindowsAWSDrivers                                   |  Automation   |  JSON   |  Windows   |  MacOS     |  None      |  0.3    |  None                                        |
|  13    |  AWSEC2-CloneInstanceAndUpgradeSQLServer                               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  18    |  AWSEC2-CloneInstanceAndUpgradeWindows                                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  6     |  AWSEC2-CloneInstanceAndUpgradeWindows2019                             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  3     |  AWSEC2-SQLServerDBRestore                                             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSDocs-ClassicLoadBalancerSSMDocument                                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSDocs-Configure-SSL-TLS-AL                                          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSDocs-Configure-SSL-TLS-AL2                                         |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  4     |  AWSDocs-HostingAWordPressBlog-AL                                      |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  4     |  AWSDocs-HostingAWordPressBlog-AL2                                     |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSDocs-IncreaseAppAvailability                                       |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  5     |  AWSDocs-InstallALAMPServer-AL                                         |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  5     |  AWSDocs-InstallALAMPServer-AL2                                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSDocs-LambdaWithS3SSMDocument                                       |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSDocs-S3StaticWebsite                                               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSDocs-S3StaticWebsiteCustomDomain                                   |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSDocs-ScaleLoadBalanced                                             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSConfigRemediation-CancelKeyDeletion                                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::KMS::Key                              |
|  1     |  AWSConfigRemediation-ConfigureCodeBuildProjectWithKMSCMK              |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CodeBuild::Project                    |
|  1     |  AWSConfigRemediation-ConfigureLambdaFunctionXRayTracing               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Lambda::Function                      |
|  1     |  AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::S3::Bucket                            |
|  2     |  AWSConfigRemediation-ConfigureS3PublicAccessBlock                     |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  2     |  AWSConfigRemediation-CreateCloudTrailMultiRegionTrail                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudTrail::Trail                     |
|  1     |  AWSConfigRemediation-CreateGuardDutyDetector                          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  None                                        |
|  1     |  AWSConfigRemediation-DeleteAPIGatewayStage                            |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ApiGateway::Stage                     |
|  1     |  AWSConfigRemediation-DeleteAccessKeysFromCodeBuildProject             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CodeBuild::Project                    |
|  1     |  AWSConfigRemediation-DeleteDefaultVPCRoutes                           |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::RouteTable                       |
|  1     |  AWSConfigRemediation-DeleteDynamoDbTable                              |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::DynamoDB::Table                       |
|  1     |  AWSConfigRemediation-DeleteEgressOnlyInternetGateway                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::EgressOnlyInternetGateway        |
|  1     |  AWSConfigRemediation-DeleteElasticsearchDomain                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Elasticsearch::Domain                 |
|  1     |  AWSConfigRemediation-DeleteIAMRole                                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::IAM:Role                              |
|  1     |  AWSConfigRemediation-DeleteIAMUser                                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::IAM::User                             |
|  1     |  AWSConfigRemediation-DeleteLambdaFunction                             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Lambda::Function                      |
|  1     |  AWSConfigRemediation-DeleteRDSCluster                                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBCluster                        |
|  1     |  AWSConfigRemediation-DeleteRDSClusterSnapshot                         |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBClusterSnapshot                |
|  1     |  AWSConfigRemediation-DeleteRDSInstance                                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-DeleteRDSInstanceSnapshot                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-DeleteRedshiftCluster                            |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Redshift::Cluster                     |
|  1     |  AWSConfigRemediation-DeleteSecret                                     |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::SecretsManager::Secret                |
|  2     |  AWSConfigRemediation-DeleteUnusedEBSVolume                            |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Volume                           |
|  1     |  AWSConfigRemediation-DeleteUnusedENI                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::NetworkInterface                 |
|  1     |  AWSConfigRemediation-DeleteUnusedIAMGroup                             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::IAM::Group                            |
|  1     |  AWSConfigRemediation-DeleteUnusedIAMPolicy                            |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::IAM::Policy                           |
|  1     |  AWSConfigRemediation-DeleteUnusedSecurityGroup                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::SecurityGroup                    |
|  1     |  AWSConfigRemediation-DeleteUnusedVPCNetworkACL                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::NetworkAcl                       |
|  1     |  AWSConfigRemediation-DeleteVPCFlowLog                                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::FlowLog                          |
|  1     |  AWSConfigRemediation-DetachAndDeleteInternetGateway                   |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::InternetGateway                  |
|  1     |  AWSConfigRemediation-DetachAndDeleteVirtualPrivateGateway             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::VPNGateway                       |
|  1     |  AWSConfigRemediation-DetachIAMPolicy                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::IAM::Policy                           |
|  1     |  AWSConfigRemediation-DisablePublicAccessToRDSInstance                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-DisablePublicAccessToRedshiftCluster             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Redshift::Cluster                     |
|  1     |  AWSConfigRemediation-DisableSubnetAutoAssignPublicIP                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Subnet                           |
|  1     |  AWSConfigRemediation-DropInvalidHeadersForALB                         |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ElasticLoadBalancingV2::LoadBalancer  |
|  1     |  AWSConfigRemediation-EnableAPIGatewayTracing                          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ApiGateway::Stage                     |
|  1     |  AWSConfigRemediation-EnableAccountAccessAnalyzer                      |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::AccessAnalyzer::Analyzer              |
|  1     |  AWSConfigRemediation-EnableAutoScalingGroupELBHealthCheck             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::AutoScaling::AutoScalingGroup         |
|  1     |  AWSConfigRemediation-EnableBeanstalkEnvironmentNotifications          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ElasticBeanstalk::Environment         |
|  1     |  AWSConfigRemediation-EnableCLBCrossZoneLoadBalancing                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ElasticLoadBalancing::LoadBalancer    |
|  1     |  AWSConfigRemediation-EnableCWLoggingForSessionManager                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::SSM::Document                         |
|  1     |  AWSConfigRemediation-EnableCloudFrontAccessLogs                       |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudFront::Distribution              |
|  1     |  AWSConfigRemediation-EnableCloudFrontDefaultRootObject                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudFront::Distribution              |
|  1     |  AWSConfigRemediation-EnableCloudFrontOriginAccessIdentity             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudFront::Distribution              |
|  1     |  AWSConfigRemediation-EnableCloudFrontOriginFailover                   |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudFront::Distribution              |
|  1     |  AWSConfigRemediation-EnableCloudFrontViewerPolicyHTTPS                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudFront::Distribution              |
|  1     |  AWSConfigRemediation-EnableCloudTrailEncryptionWithKMS                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudTrail::Trail                     |
|  1     |  AWSConfigRemediation-EnableCloudTrailLogFileValidation                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::CloudTrail::Trail                     |
|  1     |  AWSConfigRemediation-EnableCopyTagsToSnapshotOnRDSCluster             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBCluster                        |
|  1     |  AWSConfigRemediation-EnableCopyTagsToSnapshotOnRDSDBInstance          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::Instance                         |
|  1     |  AWSConfigRemediation-EnableELBDeletionProtection                      |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ElasticLoadBalancingV2::LoadBalancer  |
|  1     |  AWSConfigRemediation-EnableEbsEncryptionByDefault                     |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::::Account                             |
|  1     |  AWSConfigRemediation-EnableElasticBeanstalkEnvironmentLogStreaming    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ElasticBeanstalk::Environment         |
|  1     |  AWSConfigRemediation-EnableEncryptionOnDynamoDbTable                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::DynamoDB::Table                       |
|  2     |  AWSConfigRemediation-EnableEnhancedMonitoringOnRDSInstance            |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-EnableKeyRotation                                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::KMS::Key                              |
|  1     |  AWSConfigRemediation-EnableLoggingForALBAndCLB                        |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ElasticLoadBalancing::LoadBalancer    |
|  1     |  AWSConfigRemediation-EnableMinorVersionUpgradeOnRDSDBInstance         |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-EnableMultiAZOnRDSInstance                       |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-EnableNLBCrossZoneLoadBalancing                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ElasticLoadBalancingV2::LoadBalancer  |
|  1     |  AWSConfigRemediation-EnablePITRForDynamoDbTable                       |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::DynamoDB::Table                       |
|  1     |  AWSConfigRemediation-EnablePerformanceInsightsOnRDSInstance           |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-EnableRDSClusterDeletionProtection               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBCluster                        |
|  1     |  AWSConfigRemediation-EnableRDSInstanceBackup                          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-EnableRDSInstanceDeletionProtection              |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-EnableRedshiftClusterAuditLogging                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Redshift::Cluster                     |
|  1     |  AWSConfigRemediation-EnableRedshiftClusterAutomatedSnapshot           |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Redshift::Cluster                     |
|  1     |  AWSConfigRemediation-EnableRedshiftClusterEncryption                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Redshift::Cluster                     |
|  1     |  AWSConfigRemediation-EnableRedshiftClusterEnhancedVPCRouting          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Redshift::Cluster                     |
|  1     |  AWSConfigRemediation-EnableSecurityHub                                |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::SecurityHub::Hub                      |
|  1     |  AWSConfigRemediation-EnableSystemsManagerSessionManagerAuditLogsToS3  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::SSM::Document                         |
|  1     |  AWSConfigRemediation-EnableVPCFlowLogsToCloudWatch                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::FlowLog                          |
|  1     |  AWSConfigRemediation-EnableVPCFlowLogsToS3Bucket                      |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::FlowLog                          |
|  1     |  AWSConfigRemediation-EnableWAFClassicRegionalLogging                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::WAFRegional::WebACL                   |
|  1     |  AWSConfigRemediation-EncryptLambdaEnvironmentVariablesWithCMK         |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Lambda::Function                      |
|  1     |  AWSConfigRemediation-EncryptSNSTopic                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::SNS::Topic                            |
|  1     |  AWSConfigRemediation-EnforceEC2InstanceIMDSv2                         |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  1     |  AWSConfigRemediation-EnforceHttpsOnEsDomain                           |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Elasticsearch::Domain                 |
|  1     |  AWSConfigRemediation-EnforceSSLOnlyConnectionsToRedshiftCluster       |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Redshift::Cluster                     |
|  1     |  AWSConfigRemediation-ModifyEBSVolumeType                              |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Volume                           |
|  1     |  AWSConfigRemediation-ModifyRDSInstancePortNumber                      |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::RDS::DBInstance                       |
|  1     |  AWSConfigRemediation-ModifyRedshiftClusterMaintenanceSettings         |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Redshift::Cluster                     |
|  1     |  AWSConfigRemediation-ModifyRedshiftClusterNodeType                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Redshift::Cluster                     |
|  1     |  AWSConfigRemediation-MoveLambdaToVPC                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Lambda::Function                      |
|  1     |  AWSConfigRemediation-RemovePrincipalStarFromS3BucketPolicy            |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::S3::Bucket                            |
|  1     |  AWSConfigRemediation-RemoveUnrestrictedSourceIngressRules             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::SecurityGroup                    |
|  1     |  AWSConfigRemediation-RemoveUserPolicies                               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::IAM::User                             |
|  1     |  AWSConfigRemediation-RemoveVPCDefaultSecurityGroupRules               |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::SecurityGroup                    |
|  1     |  AWSConfigRemediation-ReplaceIAMInlinePolicy                           |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::IAM::Policy                           |
|  1     |  AWSConfigRemediation-RestrictBucketSSLRequestsOnly                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::S3::Bucket                            |
|  1     |  AWSConfigRemediation-RevokeUnusedIAMUserCredentials                   |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Lambda::Function                      |
|  1     |  AWSConfigRemediation-RotateSecret                                     |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::SecretsManager::Secret                |
|  1     |  AWSConfigRemediation-SetIAMPasswordPolicy                             |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::::Account                             |
|  1     |  AWSConfigRemediation-UpdateAPIGatewayMethodCaching                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::ApiGateway::Stage                     |
|  1     |  AWSConfigRemediation-UpdateElasticsearchDomainSecurityGroups          |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::Elasticsearch::Domain                 |
|  1     |  AWSConfigRemediation-UpdateXRayKMSKey                                 |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::XRay::EncryptionConfig                |
|  2     |  AWSSQLServer-Backup                                                   |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  2     |  AWSSQLServer-DBCC                                                     |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  2     |  AWSSQLServer-Index                                                    |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
|  2     |  AWSSQLServer-Restore                                                  |  Automation   |  YAML   |  Windows   |  Linux     |  MacOS     |  0.3    |  /AWS::EC2::Instance                         |
+--------+------------------------------------------------------------------------+---------------+---------+------------+------------+------------+---------+----------------------------------------------+

```



