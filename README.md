# amazon-ec2-update-ami
Automatically update the AMI using AWS Systems Manager's Automation Document

## Shared document information provided by AWS (2021/2/5)

$ aws ssm list-documents --no-cli-pager --output table --filters "Key=Owner,Values=Amazon" --query "sort(DocumentIdentifiers[].Name)"


--------------------------------------------------------------------------
|                              ListDocuments                             |
--------------------------------------------------------------------------

+------------------------------------------------------------------------+
|  AWS-ASGEnterStandby                                                   |
|  AWS-ASGExitStandby                                                    |
|  AWS-ApplyAnsiblePlaybooks                                             |
|  AWS-ApplyChefRecipes                                                  |
|  AWS-ApplyDSCMofs                                                      |
|  AWS-ApplyPatchBaseline                                                |
|  AWS-AttachEBSVolume                                                   |
|  AWS-AttachIAMToInstance                                               |
|  AWS-ConfigureAWSPackage                                               |
|  AWS-ConfigureCloudTrailLogging                                        |
|  AWS-ConfigureCloudWatch                                               |
|  AWS-ConfigureCloudWatchOnEC2Instance                                  |
|  AWS-ConfigureDocker                                                   |
|  AWS-ConfigureKernelLivePatching                                       |
|  AWS-ConfigureS3BucketLogging                                          |
|  AWS-ConfigureS3BucketVersioning                                       |
|  AWS-ConfigureWindowsUpdate                                            |
|  AWS-CopySnapshot                                                      |
|  AWS-CreateDynamoDbBackup                                              |
|  AWS-CreateImage                                                       |
|  AWS-CreateJiraIssue                                                   |
|  AWS-CreateManagedLinuxInstance                                        |
|  AWS-CreateManagedLinuxInstanceWithApproval                            |
|  AWS-CreateManagedWindowsInstance                                      |
|  AWS-CreateManagedWindowsInstanceWithApproval                          |
|  AWS-CreateRdsSnapshot                                                 |
|  AWS-CreateServiceNowIncident                                          |
|  AWS-CreateSnapshot                                                    |
|  AWS-DeleteCloudFormationStack                                         |
|  AWS-DeleteCloudFormationStackWithApproval                             |
|  AWS-DeleteDynamoDbBackup                                              |
|  AWS-DeleteDynamoDbTableBackups                                        |
|  AWS-DeleteEKSCluster                                                  |
|  AWS-DeleteEbsVolumeSnapshots                                          |
|  AWS-DeleteImage                                                       |
|  AWS-DeleteSnapshot                                                    |
|  AWS-DetachEBSVolume                                                   |
|  AWS-DisablePublicAccessForSecurityGroup                               |
|  AWS-DisableS3BucketPublicReadWrite                                    |
|  AWS-EnableCloudTrail                                                  |
|  AWS-EnableExplorer                                                    |
|  AWS-EnableS3BucketEncryption                                          |
|  AWS-ExportOpsDataToS3                                                 |
|  AWS-FindWindowsUpdates                                                |
|  AWS-GatherSoftwareInventory                                           |
|  AWS-HelloWorld                                                        |
|  AWS-HelloWorldChangeTemplate                                          |
|  AWS-InstallApplication                                                |
|  AWS-InstallMissingWindowsUpdates                                      |
|  AWS-InstallPowerShellModule                                           |
|  AWS-InstallSpecificWindowsUpdates                                     |
|  AWS-InstallWindowsUpdates                                             |
|  AWS-JoinDirectoryServiceDomain                                        |
|  AWS-ListWindowsInventory                                              |
|  AWS-PasswordReset                                                     |
|  AWS-PatchAsgInstance                                                  |
|  AWS-PatchInstanceWithRollback                                         |
|  AWS-PublishSNSNotification                                            |
|  AWS-RebootRdsInstance                                                 |
|  AWS-RefreshAssociation                                                |
|  AWS-ReleaseElasticIP                                                  |
|  AWS-ResizeInstance                                                    |
|  AWS-RestartEC2Instance                                                |
|  AWS-RestartEC2InstanceWithApproval                                    |
|  AWS-RunAnsiblePlaybook                                                |
|  AWS-RunCfnLint                                                        |
|  AWS-RunDockerAction                                                   |
|  AWS-RunDocument                                                       |
|  AWS-RunInspecChecks                                                   |
|  AWS-RunPacker                                                         |
|  AWS-RunPatchBaseline                                                  |
|  AWS-RunPatchBaselineAssociation                                       |
|  AWS-RunPatchBaselineWithHooks                                         |
|  AWS-RunPowerShellScript                                               |
|  AWS-RunRemoteScript                                                   |
|  AWS-RunSaltState                                                      |
|  AWS-RunShellScript                                                    |
|  AWS-SetupInventory                                                    |
|  AWS-SetupManagedInstance                                              |
|  AWS-SetupManagedRoleOnEc2Instance                                     |
|  AWS-StartEC2Instance                                                  |
|  AWS-StartEC2InstanceWithApproval                                      |
|  AWS-StartInteractiveCommand                                           |
|  AWS-StartPortForwardingSession                                        |
|  AWS-StartPortForwardingSessionToSocket                                |
|  AWS-StartRdsInstance                                                  |
|  AWS-StartSSHSession                                                   |
|  AWS-StopEC2Instance                                                   |
|  AWS-StopEC2InstanceWithApproval                                       |
|  AWS-StopRdsInstance                                                   |
|  AWS-TerminateEC2Instance                                              |
|  AWS-TerminateEC2InstanceWithApproval                                  |
|  AWS-UpdateCloudFormationStack                                         |
|  AWS-UpdateCloudFormationStackWithApproval                             |
|  AWS-UpdateEC2Config                                                   |
|  AWS-UpdateEKSManagedNodegroupVersion                                  |
|  AWS-UpdateLinuxAmi                                                    |
|  AWS-UpdateSSMAgent                                                    |
|  AWS-UpdateWindowsAmi                                                  |
|  AWSCodeDeployAgent                                                    |
|  AWSConfigRemediation-ConfigureCodeBuildProjectWithKMSCMK              |
|  AWSConfigRemediation-ConfigureLambdaFunctionXRayTracing               |
|  AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock               |
|  AWSConfigRemediation-ConfigureS3PublicAccessBlock                     |
|  AWSConfigRemediation-CreateGuardDutyDetector                          |
|  AWSConfigRemediation-DeleteAPIGatewayStage                            |
|  AWSConfigRemediation-DeleteAccessKeysFromCodeBuildProject             |
|  AWSConfigRemediation-DeleteDefaultVPCRoutes                           |
|  AWSConfigRemediation-DeleteDynamoDbTable                              |
|  AWSConfigRemediation-DeleteEgressOnlyInternetGateway                  |
|  AWSConfigRemediation-DeleteIAMRole                                    |
|  AWSConfigRemediation-DeleteLambdaFunction                             |
|  AWSConfigRemediation-DeleteRDSCluster                                 |
|  AWSConfigRemediation-DeleteRDSInstanceSnapshot                        |
|  AWSConfigRemediation-DeleteRedshiftCluster                            |
|  AWSConfigRemediation-DeleteUnusedEBSVolume                            |
|  AWSConfigRemediation-DeleteUnusedENI                                  |
|  AWSConfigRemediation-DeleteUnusedIAMGroup                             |
|  AWSConfigRemediation-DeleteUnusedSecurityGroup                        |
|  AWSConfigRemediation-DeleteUnusedVPCNetworkACL                        |
|  AWSConfigRemediation-DetachIAMPolicy                                  |
|  AWSConfigRemediation-DisableSubnetAutoAssignPublicIP                  |
|  AWSConfigRemediation-EnableAPIGatewayTracing                          |
|  AWSConfigRemediation-EnableAccountAccessAnalyzer                      |
|  AWSConfigRemediation-EnableCLBCrossZoneLoadBalancing                  |
|  AWSConfigRemediation-EnableCloudFrontOriginAccessIdentity             |
|  AWSConfigRemediation-EnableCloudFrontOriginFailover                   |
|  AWSConfigRemediation-EnableCloudFrontViewerPolicyHTTPS                |
|  AWSConfigRemediation-EnableCopyTagsToSnapshotOnRDSCluster             |
|  AWSConfigRemediation-EnableCopyTagsToSnapshotOnRDSDBInstance          |
|  AWSConfigRemediation-EnableELBDeletionProtection                      |
|  AWSConfigRemediation-EnableEbsEncryptionByDefault                     |
|  AWSConfigRemediation-EnableElasticBeanstalkEnvironmentLogStreaming    |
|  AWSConfigRemediation-EnableEncryptionOnDynamoDbTable                  |
|  AWSConfigRemediation-EnableEnhancedMonitoringOnRDSInstance            |
|  AWSConfigRemediation-EnableKeyRotation                                |
|  AWSConfigRemediation-EnableMinorVersionUpgradeOnRDSDBInstance         |
|  AWSConfigRemediation-EnableMultiAZOnRDSInstance                       |
|  AWSConfigRemediation-EnableNLBCrossZoneLoadBalancing                  |
|  AWSConfigRemediation-EnablePITRForDynamoDbTable                       |
|  AWSConfigRemediation-EnablePerformanceInsightsOnRDSInstance           |
|  AWSConfigRemediation-EnableRDSClusterDeletionProtection               |
|  AWSConfigRemediation-EnableRDSInstanceBackup                          |
|  AWSConfigRemediation-EnableRDSInstanceDeletionProtection              |
|  AWSConfigRemediation-EnableRedshiftClusterAuditLogging                |
|  AWSConfigRemediation-EnableRedshiftClusterAutomatedSnapshot           |
|  AWSConfigRemediation-EnableRedshiftClusterEncryption                  |
|  AWSConfigRemediation-EnableRedshiftClusterEnhancedVPCRouting          |
|  AWSConfigRemediation-EnableSecurityHub                                |
|  AWSConfigRemediation-EnableSystemsManagerSessionManagerAuditLogsToS3  |
|  AWSConfigRemediation-EnableWAFClassicRegionalLogging                  |
|  AWSConfigRemediation-EncryptLambdaEnvironmentVariablesWithCMK         |
|  AWSConfigRemediation-EncryptSNSTopic                                  |
|  AWSConfigRemediation-EnforceEC2InstanceIMDSv2                         |
|  AWSConfigRemediation-EnforceHttpsOnEsDomain                           |
|  AWSConfigRemediation-EnforceSSLOnlyConnectionsToRedshiftCluster       |
|  AWSConfigRemediation-ModifyRDSInstancePortNumber                      |
|  AWSConfigRemediation-ModifyRedshiftClusterMaintenanceSettings         |
|  AWSConfigRemediation-ModifyRedshiftClusterNodeType                    |
|  AWSConfigRemediation-MoveLambdaToVPC                                  |
|  AWSConfigRemediation-RemoveVPCDefaultSecurityGroupRules               |
|  AWSConfigRemediation-RevokeUnusedIAMUserCredentials                   |
|  AWSConfigRemediation-RotateSecret                                     |
|  AWSConfigRemediation-SetIAMPasswordPolicy                             |
|  AWSConfigRemediation-UpdateElasticsearchDomainSecurityGroups          |
|  AWSConfigRemediation-UpdateXRayKMSKey                                 |
|  AWSDocs-ClassicLoadBalancerSSMDocument                                |
|  AWSDocs-Configure-SSL-TLS-AL                                          |
|  AWSDocs-Configure-SSL-TLS-AL2                                         |
|  AWSDocs-HostingAWordPressBlog-AL                                      |
|  AWSDocs-HostingAWordPressBlog-AL2                                     |
|  AWSDocs-IncreaseAppAvailability                                       |
|  AWSDocs-InstallALAMPServer-AL                                         |
|  AWSDocs-InstallALAMPServer-AL2                                        |
|  AWSDocs-LambdaWithS3SSMDocument                                       |
|  AWSDocs-S3StaticWebsite                                               |
|  AWSDocs-S3StaticWebsiteCustomDomain                                   |
|  AWSDocs-ScaleLoadBalanced                                             |
|  AWSEC2-ApplicationInsightsCloudwatchAgentInstallAndConfigure          |
|  AWSEC2-CheckPerformanceCounterSets                                    |
|  AWSEC2-CloneInstanceAndUpgradeSQLServer                               |
|  AWSEC2-CloneInstanceAndUpgradeWindows                                 |
|  AWSEC2-CloneInstanceAndUpgradeWindows2019                             |
|  AWSEC2-ConfigureSTIG                                                  |
|  AWSEC2-CreateVssSnapshot                                              |
|  AWSEC2-DetectWorkload                                                 |
|  AWSEC2-ManageVssIO                                                    |
|  AWSEC2-RunSysprep                                                     |
|  AWSEC2-SQLServerDBRestore                                             |
|  AWSEC2Launch-Agent                                                    |
|  AWSEC2Launch-RunMigration                                             |
|  AWSFleetManager-AddUsersToGroups                                      |
|  AWSFleetManager-CreateGroup                                           |
|  AWSFleetManager-CreateUser                                            |
|  AWSFleetManager-CreateUserInteractive                                 |
|  AWSFleetManager-CreateWindowsRegistryKey                              |
|  AWSFleetManager-DeleteGroup                                           |
|  AWSFleetManager-DeleteUser                                            |
|  AWSFleetManager-DeleteWindowsRegistryKey                              |
|  AWSFleetManager-DeleteWindowsRegistryValue                            |
|  AWSFleetManager-GetFileContent                                        |
|  AWSFleetManager-GetFileSystemContent                                  |
|  AWSFleetManager-GetGroups                                             |
|  AWSFleetManager-GetPerformanceCounters                                |
|  AWSFleetManager-GetUsers                                              |
|  AWSFleetManager-GetWindowsEvents                                      |
|  AWSFleetManager-GetWindowsRegistryContent                             |
|  AWSFleetManager-RemoveUsersFromGroups                                 |
|  AWSFleetManager-SetWindowsRegistryValue                               |
|  AWSKinesisTap                                                         |
|  AWSNVMe                                                               |
|  AWSObservabilityExporter-JMXExporterInstallAndConfigure               |
|  AWSPVDriver                                                           |
|  AWSSAP-Backint                                                        |
|  AWSSAP-InstallBackint                                                 |
|  AWSSQLServer-Backup                                                   |
|  AWSSQLServer-DBCC                                                     |
|  AWSSQLServer-Index                                                    |
|  AWSSQLServer-Restore                                                  |
|  AWSSupport-ActivateWindowsWithAmazonLicense                           |
|  AWSSupport-CheckAndMountEFS                                           |
|  AWSSupport-CollectEKSInstanceLogs                                     |
|  AWSSupport-ConnectivityTroubleshooter                                 |
|  AWSSupport-EC2Rescue                                                  |
|  AWSSupport-ExecuteEC2Rescue                                           |
|  AWSSupport-GrantPermissionsToIAMUser                                  |
|  AWSSupport-ListEC2Resources                                           |
|  AWSSupport-ManageRDPSettings                                          |
|  AWSSupport-ManageWindowsService                                       |
|  AWSSupport-RecoverWorkSpace                                           |
|  AWSSupport-RecoverWorkSpaceWithApproval                               |
|  AWSSupport-ResetAccess                                                |
|  AWSSupport-RunEC2RescueForWindowsTool                                 |
|  AWSSupport-SendLogBundleToS3Bucket                                    |
|  AWSSupport-SetupIPMonitoringFromVPC                                   |
|  AWSSupport-ShareRDSSnapshot                                           |
|  AWSSupport-StartEC2RescueWorkflow                                     |
|  AWSSupport-TerminateIPMonitoringFromVPC                               |
|  AWSSupport-TroubleshootConnectivityToRDS                              |
|  AWSSupport-TroubleshootDirectoryTrust                                 |
|  AWSSupport-TroubleshootRDP                                            |
|  AWSSupport-TroubleshootS3PublicRead                                   |
|  AWSSupport-TroubleshootSSH                                            |
|  AWSSupport-UpgradeWindowsAWSDrivers                                   |
|  AmazonCloudWatch-ManageAgent                                          |
|  AmazonCloudWatch-MigrateCloudWatchAgent                               |
|  AmazonCloudWatchAgent                                                 |
|  AmazonECS-ExecuteInteractiveCommand                                   |
|  AmazonEFSUtils                                                        |
|  AmazonInspector-ManageAWSAgent                                        |
|  AwsEnaNetworkDriver                                                   |
|  AwsVssComponents                                                      |
+------------------------------------------------------------------------+

