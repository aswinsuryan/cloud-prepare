/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package azure

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/pkg/errors"
	"github.com/submariner-io/cloud-prepare/pkg/api"
	"github.com/submariner-io/cloud-prepare/pkg/k8s"
)

type CloudInfo struct {
	SubscriptionID string
	InfraID        string
	Region         string
	BaseGroupName  string
	Authorizer     autorest.Authorizer
	K8sClient      k8s.Interface
}

func (c *CloudInfo) openInternalPorts(infraID string, ports []api.PortSpec,
	networkClient *network.SecurityGroupsClient, subnetClient *network.SubnetsClient, reporter api.Reporter) error {
	groupName := infraID + internalSecurityGroupSuffix

	isFound := checkIfSecurityGroupPresent(groupName, networkClient, c.BaseGroupName)
	if isFound {
		return nil
	}

	securityRules := []network.SecurityRule{}
	for i, port := range ports {
		securityRules = append(securityRules, c.createSecurityRule(allNetworkCIDR, allNetworkCIDR, port.Protocol,
			port.Port, int32(basePriority+i)))
	}

	vnetName := infraID + "-vnet"
	workerSubnetName := infraID + "-worker-subnet"
	masterSubnetName := infraID + "-master-subnet"

	workerSubnet, err := getSubnet(vnetName, workerSubnetName, c.BaseGroupName, subnetClient)
	if err != nil {
		return errors.Wrapf(err, "failed to retrieve subnet %q", infraID+"-worker-subnet")
	}

	masterSubnet, err := getSubnet(vnetName, masterSubnetName, c.BaseGroupName, subnetClient)
	if err != nil {
		return errors.Wrapf(err, "failed to retrieve subnet %q", infraID+"-master-subnet")
	}

	reporter.Started(fmt.Sprintf("The subnets are masterSubnet = %v , workerSubnet = %v", workerSubnet, masterSubnet))
	subnets := []network.Subnet{*workerSubnet, *masterSubnet}
	nwSecurityGroup := network.SecurityGroup{
		Name:     &groupName,
		Location: to.StringPtr(c.Region),
		SecurityGroupPropertiesFormat: &network.SecurityGroupPropertiesFormat{
			SecurityRules: &securityRules,
			Subnets:       &subnets,
		},
	}
	reporter.Succeeded(fmt.Sprintf("The subnets %v", nwSecurityGroup.Subnets))

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	future, err := networkClient.CreateOrUpdate(ctx, c.BaseGroupName, groupName, nwSecurityGroup)
	if err != nil {
		return errors.Wrapf(err, "creating security group %q failed", groupName)
	}

	err = future.WaitForCompletionRef(ctx, networkClient.Client)

	return errors.Wrapf(err, "Error creating  security group %v ", groupName)
}

func (c *CloudInfo) removeInternalFirewallRules(infraID string, sgClient *network.SecurityGroupsClient) error {
	groupName := infraID + internalSecurityGroupSuffix

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	nwSecurityGroup, err := sgClient.Get(ctx, c.BaseGroupName, groupName, "")
	if err != nil {
		return errors.Wrapf(err, "error getting the securitygroup %q", groupName)
	}

	nwSecurityGroup.SecurityGroupPropertiesFormat.Subnets = nil

	updateFuture, err := sgClient.CreateOrUpdate(ctx, c.BaseGroupName, groupName, nwSecurityGroup)

	if err != nil {
		return errors.Wrapf(err, "removing security group %q from subnets failed", groupName)
	}

	err = updateFuture.WaitForCompletionRef(ctx, sgClient.Client)

	if err != nil {
		return errors.Wrapf(err, "waiting for security group  %q to be updated failed", groupName)
	}

	deleteFuture, err := sgClient.Delete(ctx, c.BaseGroupName, groupName)
	if err != nil {
		return errors.Wrapf(err, "deleting security group %q failed", groupName)
	}

	err = deleteFuture.WaitForCompletionRef(ctx, sgClient.Client)

	if err != nil {
		return errors.Wrapf(err, "waiting for security group  %q to be deleted failed", groupName)
	}

	return errors.WithMessage(err, "failed to remove security group from servers")
}

func checkIfSecurityGroupPresent(groupName string, networkClient *network.SecurityGroupsClient, baseGroupName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	_, err := networkClient.Get(ctx, baseGroupName, groupName, "")

	return err == nil
}

func getSubnet(virtualNetworkName, subnetName, baseGroupName string, subnetsClient *network.SubnetsClient) (*network.Subnet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	subnet, err := subnetsClient.Get(ctx, baseGroupName, virtualNetworkName, subnetName, "")
	if err != nil {
		return nil, errors.Wrapf(err, "error getting the subnet %q", err)
	}

	return &subnet, nil
}

func (c *CloudInfo) createSecurityRule(srcIPPrefix, destIPPrefix, protocol string, port uint16, priority int32,
) network.SecurityRule {
	return network.SecurityRule{
		Name: to.StringPtr(internalSecurityRulePrefix + protocol + "-" + strconv.Itoa(int(port))),
		SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
			Protocol:                 network.SecurityRuleProtocol(protocol),
			DestinationPortRange:     to.StringPtr(strconv.Itoa(int(port)) + "-" + strconv.Itoa(int(port))),
			SourceAddressPrefix:      &srcIPPrefix,
			DestinationAddressPrefix: &destIPPrefix,
			SourcePortRange:          to.StringPtr("*"),
			Access:                   network.SecurityRuleAccessAllow,
			Direction:                network.SecurityRuleDirectionInbound,
			Priority:                 to.Int32Ptr(priority),
		},
	}
}
