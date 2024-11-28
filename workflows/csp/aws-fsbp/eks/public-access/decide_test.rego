package policy.aws.eks.public_access

import data.shisho
import future.keywords

test_public_access_of_eks_clusters_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"eks": {"clusters": [
		{
			"metadata": {
				"id": "aws-eks-cluster|ap-northeast-1|test-cluster-1",
				"displayName": "test-cluster-1",
			},
			"resourcesVpcConfiguration": {"endpointPublicAccess": false, "publicAccessCidrs": []},
			"tags": [],
		},
		{
			"metadata": {
				"id": "aws-eks-cluster|ap-northeast-1|test-cluster-2",
				"displayName": "test-cluster-2",
			},
			"resourcesVpcConfiguration": {"endpointPublicAccess": false, "publicAccessCidrs": []},
			"tags": [],
		},
	]}}]}}
}

test_public_access_of_eks_clusters_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"eks": {"clusters": [
		{
			"metadata": {
				"id": "aws-eks-cluster|ap-northeast-1|test-cluster-1",
				"displayName": "test-cluster-1",
			},
			"resourcesVpcConfiguration": {"endpointPublicAccess": true, "publicAccessCidrs": []},
			"tags": [],
		},
		{
			"metadata": {
				"id": "aws-eks-cluster|ap-northeast-1|test-cluster-2",
				"displayName": "test-cluster-2",
			},
			"resourcesVpcConfiguration": {"endpointPublicAccess": true, "publicAccessCidrs": []},
			"tags": [],
		},
	]}}]}}
}
