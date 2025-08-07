---
date: 2025-08-04
# categories:
#   - AWS
#   - EKS
#   - kubernetes
slug: eks-hardening-blocking-pod-level-access-to-imds
title: "EKS Hardening: Blocking Pod-Level Access to IMDS"
summary: "Effectively securing pods inside an EKS cluster, swirling with cloud permissions, has always been challenging. Is it possible to close off a well-known source of risk, while still ensuring basic functionality?"
---

# EKS Hardening: Blocking Pod-Level Access to IMDS

*Effectively securing pods inside an EKS cluster, swirling with cloud permissions, has always been challenging. Is it possible to close off a well-known source of risk, while still ensuring basic functionality?*

<!-- more -->

## Introduction
The principle of role-based access control (RBAC) within kubernetes is built on a simple idea - supplying only the permissions required by an individual process (pod, in this case) in order for it to do its job. There's a lot riding on this control: get it right, and pods managing all kinds of different workloads can safely operate alongside each other in a common environment; get it wrong though, and there is the very real risk of simple vulnerabilities escalating into potentially disastrous outcomes.

The situation isn't helped by the fact that, within a kubernetes cluster, not all players are equal. Pods may only need basic permissions to perform their specific task (pulling messages from SQS, writing files to S3 etc.) but something has to provide the resources for those pods to run on, which is the role of the worker nodes. These nodes require access at a more fundamental (and impactful) level - they need to be able to pull the images that run the workloads, as well as understand the resources and configuration of the environment they exist within.

A lot of this functionality is handled via the Internal Metadata Service (IMDS), a locally-accessible API that provides access to configuration data, as well as the credentials needed for the node to authenticate itself. IMDS was never intended to service anything but the hosting node, but the nature of the container runtime (EKS uses [containerd](https://containerd.io/)) means that pods are simply processes running atop the worker, allowing them to access the infamous `http://169.254.169.254` address just as easily. Since the first version of IMDS (`IMDSv1`) was built with no method of authentication, as well as being vulnerable to server-side request forgery (SSRF), this enabled a straightforward path to privilege escalation that resulted in a number of high-profile incidents, such as the [Capital One data breach](https://dl.acm.org/doi/full/10.1145/3546068) in 2019.

In response, Amazon introduced [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) and took a major step forward in reducing this risk, by mandating that use of the metadata API must first involve generation of a session token via an `HTTP PUT` request. This token must then be supplied via a header in all subsequent requests. Asssuming that IMDSv2 is not just enabled but actually *enforced*, this prevents an attacker from proxying metadata requests through a misconfigured firewall, unrestricted reverse proxy or SSRF. But it still doesn't fully address the problem.

## The Remaining Threat: RCE
By itself IMDSv2 still fails to address one class of vulnerability - remote code execution (RCE). An attacker who can execute code inside a running pod (via uploading a web-shell, discovery a command injection vulnerability  or similar) can easily help themselves to node-level access. How easily?  Simply request a session token via curl:

```sh
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)
```

then use that token to retrieve instance credentials from the node via IMDS:
```sh
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/karpenter-worker/

{
  "Code" : "Success",
  "LastUpdated" : "2025-08-04T06:23:29Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA4VDBL2NIXYVXTEPT",
  "SecretAccessKey" : "d5NB5Jr/y+018xfUdjtuNO/3Q9sxmps21bW6rGK1",
  "Token" : "IQoJb3Jp...B6alm4tBg6A==",
  "Expiration" : "2025-08-04T12:57:32Z"
}
```

These values can then be set as environment variables:

```sh
export AWS_ACCESS_KEY_ID="ASIA4VDBL2NIXYVXTEPT"
export AWS_SECRET_ACCESS_KEY="d5NB5Jr/y+018xfUdjtuNO/3Q9sxmps21bW6rGK1"
set AWS_SESSION_TOKEN="IQoJb3Jp...B6alm4tBg6A=="
```

And with very little trouble, the attacker has assumed the worker node's role:
```sh
aws sts get-caller-identity
{
    "UserId": "AROA4VDBL2CUDQE2KIGEY:i-0db92f4d7339c0c95",
    "Account": "000000000000",
    "Arn": "arn:aws:sts::000000000000:assumed-role/karpenter-worker/i-0db92f4d7339c0c95"
}
```

EKS worker nodes are typically configured with roles that include a number of AWS managed policies, enabling several privileged actions that are likely to be of interest to an attacker:

[AmazonEKSWorkerNodePolicy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEKSWorkerNodePolicy.html)
```json
{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Sid" : "WorkerNodePermissions",
      "Effect" : "Allow",
      "Action" : [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:DescribeVolumesModifications",
        "ec2:DescribeVpcs",
        "eks:DescribeCluster",
        "eks-auth:AssumeRoleForPodIdentity"
      ],
      "Resource" : "*"
    }
  ]
}
```

[AmazonEC2ContainerRegistryReadOnly](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEC2ContainerRegistryReadOnly.html)
```json
{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Action" : [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:DescribeImages",
        "ecr:BatchGetImage",
        "ecr:GetLifecyclePolicy",
        "ecr:GetLifecyclePolicyPreview",
        "ecr:ListTagsForResource",
        "ecr:DescribeImageScanFindings"
      ],
      "Resource" : "*"
    }
  ]
}
```

There are clearly a number of privileges here that would prove very useful when enumerating a cloud environnment, such as `ec2:DescribeInstances` and `ec2:DescribeSecurityGroups`. Similarly, the ability to browse through and download images from all ECR repositories (`ecr.DescribeRepositories`, `ecr.ListImages` and `ecr.GetAuthorizationToken`) are likely to yield additional sensitive information, from images typically thought of as 'private'.

To be clear, these are privileges that nodes absolutely need in order to function as part of the EKS cluster. But the risk of them being stolen from application pods running on the nodes represents a serious threat. All that it takes is for a public-facing app to be shipped with an RCE vulnerability - either through inclusion of insecure code, or the use of a vulnerable dependency - and a large part of the EKS cluster's cloud environment is exposed, even if IMDSv2 is enforced.

## The Solution: IMDS Hop Limit?
There is usually more to the story, however, and in this case it comes in the form of the [IMDS response hop limit](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html#modify-PUT-response-hop-limit). The AWS documentation outlines the purpose of this setting:

> The hop limit is the number of network hops that the PUT response is allowed to make. You can set the hop limit to a minimum of 1 and a maximum of 64.

Essentially operating as a packet-level time to live (TTL), the hop limit dictates how far across the network a token (PUT) response can travel. Setting it to the minimum value of `1` means it can only reach the calling node itself, which again is absolutely required for normal cluster operation. A value of `2` allows the response to travel up to two hops, meaning it could reach the pods running on a node - exactly where it might be attainable via RCE.

Based on this information then, it sounds like the obvious choice would be to simply set the hop limit of all nodes to `1`. The docs, however, also include a vague note of caution on this:

> In a container environment, a hop limit of 1 can cause issues.

In other words, under certain security configurations, pods may need to be able to call IMDS on their host nodes in order to perform their intended function. This could be for the purposes of obtaining credentials, or even something as seemingly harmless as identifying the region the node exists in. So while setting the IMDS hop limit to `1` might *seem* like a good way to improve security, it might also prevent pods from running at all, which is definitely not ideal. To further complicate matters, it seems that when a hop limit is not explicitly specified (via a launch template or similar) AWS will often set a default hop limit of `2`, leading many to believe that this is infact the required value for their EKS cluster to function correctly.

Clearly, there is some confusion around what is really possible with this setting. The only real way to understand the situation is to try out some different configurations, and evaluate the results.

## The Challenge
So the question becomes - can we mandate a metadata response hop limit of `1`, thereby preventing the threat of privilege escalation from a compromised pod, while still allowing pods to operate correctly?

Pod-level security mechanisms have evolved a lot over the years, to the point where there are a number of choices when it comes to management. In this post, we'll evaluate the feasability of configuring pods to successfully run on nodes with a hop limit of `1` using two common solutions:

1. IAM Roles for Service Accounts (IRSA)
2. PodIdentity

## Environment Setup
In order to easily provision worker nodes with the different hop limit configurations we need, we'll use [karpenter](https://karpenter.sh/), a high-performance kubernetes autoscaler built by AWS. We can deploy two different `EC2NodeClasses` (node configurations) into an existing EKS cluster. The first named `ec2nc-with-hop-limit-2` will set a hop limit value of `2` (the current default in our cluster):

```
apiVersion: karpenter.k8s.aws/v1beta1
kind: EC2NodeClass
metadata:
  name: ec2nc-with-hop-limit-2
spec:
  amiFamily: AL2023
  instanceProfile: KarpenterNodeInstanceProfile-${CLUSTER_NAME}
  metadataOptions:
    httpTokens:
    httpPutResponseHopLimit: 2
```

and the second named `ec2nc-with-hop-limit-1` will set a hop limit value of `1`:
```
apiVersion: karpenter.k8s.aws/v1beta1
kind: EC2NodeClass
metadata:
  name: ec2nc-with-hop-limit-1
spec:
  amiFamily: AL2023
  instanceProfile: KarpenterNodeInstanceProfile-${CLUSTER_NAME}
  metadataOptions:
    httpTokens:
    httpPutResponseHopLimit: 1
```

We then wrap these `EC2NodeClasses` in karpenter `NodePools`, which essentially just provide a way to reference & request nodes of that configuration:

```
apiVersion: karpenter.sh/v1beta1
kind: NodePool
metadata:
  name: np-with-hop-limit-2
spec:
  template:
    spec:
      requirements:
      ...
      nodeClassRef:
        apiVersion: karpenter.k8s.aws/v1beta1
        kind: EC2NodeClass
        name: ec2nc-with-hop-limit-2
  ...
```

```
apiVersion: karpenter.sh/v1beta1
kind: NodePool
metadata:
  name: np-with-hop-limit-1
spec:
  template:
    spec:
      requirements:
      ...
      nodeClassRef:
        apiVersion: karpenter.k8s.aws/v1beta1
        kind: EC2NodeClass
        name: ec2nc-with-hop-limit-1
  ...
```

In order the assess whether pods running on these two different `NodePools` can still interact with AWS resources in a functioning way, we'll use a basic pod spec that starts an alpine linux container that can be used to issue aws cli commands:

```
apiVersion: v1
kind: Pod
metadata:
  name: hop-limit-demo-app
spec:
  containers:
  - name: demo-app
    image: alpine:latest
    command: ["tail", "-f", "/dev/null"]
  nodeSelector:
    nodepool: # set to either np-with-hop-limit-2 or np-with-hop-limit-1
```

With the demo pod deployed to both `NodePools`, we can immediately see the effect of setting `httpPutResponseHopLimit` via the `EC2NodeClass`. When running on a node using the `ec2nc-with-hop-limit-2` configuration, token requests from the pod to IMDS work as normal:
```sh
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -v
*   Trying 169.254.169.254:80...
* Connected to 169.254.169.254 (169.254.169.254) port 80
* using HTTP/1.x
> PUT /latest/api/token HTTP/1.1
> Host: 169.254.169.254
> User-Agent: curl/8.14.1
> Accept: */*
> X-aws-ec2-metadata-token-ttl-seconds: 21600
>
< HTTP/1.1 200 OK
< X-Aws-Ec2-Metadata-Token-Ttl-Seconds: 21600
< Content-Length: 56
< Date: Wed, 30 Jul 2025 23:22:04 GMT
< Server: EC2ws
< Connection: close
< Content-Type: text/plain
<
* we are done reading and this is set to close, stop send
* abort upload
* shutting down connection #0
AQAEAIXkhdOR3sIqAVRdg0mVAdHYRr_fkfFDU7SDzH9whlWZJwANKg==/
```

Running the same request on a pod deployed using `ec2nc-with-hop-limit-1`, however, times out when requesting a token:
```sh
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -v
*   Trying 169.254.169.254:80...
* Connected to 169.254.169.254 (169.254.169.254) port 80
* using HTTP/1.x
> PUT /latest/api/token HTTP/1.1
> Host: 169.254.169.254
> User-Agent: curl/8.14.1
> Accept: */*
> X-aws-ec2-metadata-token-ttl-seconds: 21600
>
* Request completely sent off
* Recv failure: Connection reset by peer
* closing connection #0
curl: (56) Recv failure: Connection reset by peer
```

With our two testing environments prepared, we can now evaluate the pod-level mechanisms to understand if they are impacted by the hop limit.

## Experiment 1. IAM Roles for Service Accounts (IRSA)
Also released by AWS in 2019, IRSA provides a means for kubernetes workloads to access AWS services and resources, through use of [OpenID Connect (OIDC)](https://docs.aws.amazon.com/eks/latest/userguide/authenticate-oidc-identity-provider.html). In order to test our setup against IRSA, we need to modify the configuration of our demo app to include:

1. A `ServiceAccount` object, bound to an IAM role via annotation:
```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: hop-limit-demo-app-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::000000000000:role/hop-limit-demo-app-role
```

2. A reference to the `ServiceAccount` in the pod's spec:
```
spec:
  serviceAccountName: hop-limit-demo-app-sa
  containers:
  ...
```

Additionally, an IAM role `hop-limit-demo-app-role` will need to be created in the hosting AWS account, with a trust policy that allows it to be assumed via OIDC. The role also requires an IAM policy that enables the permissions our app needs to function. For the purposes of this experiment, we'll assume our demo app simply needs to be able to list and interact (put, delete, update) with objects in an S3 bucket:

```sh
aws iam create-role --role-name hop-limit-demo-app-role \
--assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/24E3DC8B5FG87CD57B2B0ZZ8D6B7079X\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"oidc.eks.us-west-2.amazonaws.com/id/24E3DC8B5FG87CD57B2B0ZZ8D6B7079X:aud\":\"sts.amazonaws.com\",\"oidc.eks.us-west-2.amazonaws.com/id/24E3DC8B5FG87CD57B2B0ZZ8D6B7079X:sub\":\"system:serviceaccount:hop-limit-demo-app:hop-limit-demo-app-sa\"}}}]}"

aws iam put-role-policy --role-name hop-limit-demo-app-role \
--policy-name hop-limit-demo-app-policy \
--policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":[\"s3:ListBucket\",\"s3:*Object\"],\"Resource\":[\"arn:aws:s3:::hop-limit-demo-app-bucket\",\"arn:aws:s3:::hop-limit-demo-app-bucket/*\"],\"Effect\":\"Allow\"}]}"
```

After creating the new IAM role & policy, and deploying the new manifests, we can confirm that the pod running on a node with a hop limit of `2` has no problems identifying itself via `get-caller-identity`:
```sh
aws sts get-caller-identity
{
    "UserId": "AROA4VDBL2NISX2M4YIVX:botocore-session-1754021985",
    "Account": "000000000000",
    "Arn": "arn:aws:sts::000000000000:assumed-role/hop-limit-demo-app-role/botocore-session-1754021985"
}
```

It's also perfectly able to perform the actions in the attached policy, including writing objects to an S3 bucket and listing the contents:
```sh
/ aws s3 cp /tmp/test.txt s3://hop-limit-demo-app-bucket/test.txt
upload: tmp/test.txt to s3://hop-limit-demo-app-bucket/test.txt

/ aws s3 ls hop-limit-demo-app-bucket
2025-08-01 04:24:40          5 test.txt
```

If the demo app is deployed to a node with hop limit of `1`, we can confirm that its privileges remain unaffected, despite no longer having access to IMDS:
```sh
aws sts get-caller-identity
{
    "UserId": "AROA4VDBL2NISX2M4YIVX:botocore-session-1754200769",
    "Account": "000000000000",
    "Arn": "arn:aws:sts::000000000000:assumed-role/hop-limit-demo-app-role/botocore-session-1754200769"
}

/ aws s3 cp /tmp/test.txt s3://hop-limit-demo-app-bucket/test.txt
upload: tmp/test.txt to s3://hop-limit-demo-app-bucket/test.txt

/ aws s3 ls hop-limit-demo-app-bucket
2025-08-01 04:26:37          6 test.txt
```

!!! success "Verdict: Successful"
    Pods running with privileges supplied via IAM Roles for Service Accounts (IRSA) are compatible with an IMDS hop limit of `1`.

## Experiment 2. PodIdentity
PodIdentity was released in 2023 as an attempt to simplify authenticating kubernetes workloads in AWS, by allowing the ServiceAccount-to-IAM-role connection (known as a `Pod Identity Association`) to be created via the EKS console or the `eksctl` CLI.

To test out this approach, we need to again create an IAM role with an appropriate permissions policy. Note that in this case however, the role's trust policy does not reference OIDC, as it plays no part in PodIdentity (a positive side-effect of PodIdentity is that a single role can be accessed from multiple EKS clusters, without needing to update the trust policy to include each cluster's unique OIDC provider):

```sh
aws iam create-role --role-name hop-limit-demo-app-role-pod-identity \
--assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"pods.eks.amazonaws.com\"},\"Action\":[\"sts:AssumeRole\", \"sts:TagSession\"]}]}"

aws iam put-role-policy --role-name hop-limit-demo-app-role-pod-identity \
--policy-name hop-limit-demo-app-pod-identity-policy \
--policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":[\"s3:ListBucket\",\"s3:*Object\"],\"Resource\":[\"arn:aws:s3:::hop-limit-demo-app-bucket\",\"arn:aws:s3:::hop-limit-demo-app-bucket/*\"],\"Effect\":\"Allow\"}]}"
```

We then create the pod identity association, that binds the IAM role to a specific service account within a single namespace:
```sh
aws eks create-pod-identity-association \
--cluster-name tmb-npd-usw2-eks \
--namespace hop-limit-demo-app \
--service-account hop-limit-demo-app-pod-identity-sa \
--role-arn arn:aws:iam::000000000000:role/hop-limit-demo-app-role-pod-identity  
```

With the new ServiceAccount `hop-limit-demo-app-pod-identity-sa` bound to the pod, we can deploy it to our two node configurations for evaluation. Running on a node with a hop limit of `2`, the pod is again able to identify itself and access the S3 bucket as expected:

```sh
aws sts get-caller-identity
{
    "UserId": "AROA4VDBL2NITVDU7NO6C:eks-demo-cluster-hop-limit--832f49b9-b135-44f3-b6a4-d586ce81119f",
    "Account": "000000000000",
    "Arn": "arn:aws:sts::000000000000:assumed-role/hop-limit-demo-app-role-pod-identity/eks-demo-cluster-hop-limit--832f49b9-b135
-44f3-b6a4-d586ce81119f"
}

/ aws s3 cp /tmp/test3.txt s3://hop-limit-demo-app-bucket/test3.txt
upload: tmp/test3.txt to s3://hop-limit-demo-app-bucket/test3.txt
/ aws s3 ls s3://hop-limit-demo-app-bucket
2025-08-03 06:18:25          6 test3.txt
```

And again, even when deployed to a node with a hop limit of `1`, the pod continues to function correctly:

```sh
aws sts get-caller-identity
{
    "UserId": "AROA4VDBL2NITVDU7NO6C:eks-demo-cluster-hop-limit--27102cfa-a547-4625-9e56-c2f863c99793",
    "Account": "000000000000",
    "Arn": "arn:aws:sts::000000000000:assumed-role/hop-limit-demo-app-role-pod-identity/eks-demo-cluster-hop-limit--27102cfa-a547
-4625-9e56-c2f863c99793"
}

/ aws s3 cp /tmp/test4.txt s3://hop-limit-demo-app-bucket/test4.txt
upload: tmp/test4.txt to s3://hop-limit-demo-app-bucket/test4.txt
/ aws s3 ls s3://hop-limit-demo-app-bucket
2025-08-03 06:20:39          6 test4.txt
```

!!! success "Verdict: Successful"
    As with IRSA, pods running with privileges supplied PodIdentity are also compatible with an IMDS hop limit of `1`.

## Results & Considerations
Based on these results, implementing pod-level authentication using either IRSA or PodIdentity seems to be compatible with nodes configured with an IMDS hop limit of `1`.

Enforcing this setting can have a meaningful impact on the security posture of an EKS cluster, by reducing the blast radius in the event that an attacker achieved pod-level RCE. As mentioned earlier, simply swapping to IMDSv2 is not enough to mitigate this kind of threat - pods need to be fully blocked from accessing the IMDS API, which is where the hop limit setting comes in to play.

Given that both experiments proved successful, a valid question becomes - is there any configuration that might be problematic with a hop limit of `1`? Some research seems to suggest a few configurations that might be problematic, neither of which is likely to affect well-architected applications running in modern infrastructure:

1. Old versions of EKS add-ons that are not fully optimised for IMDSv2 - these may still rely on IMDS to determine necessary environment details, such as AWS region, instance ID etc.

2. Custom code or scripts - any kind of code that specifically makes a request to IMDS (again, usually for retrieving envirnoment details like AWS region) will most likely break if nodes are configured with a hop limit of `1`.

## Conclusion

!!! abstract "TLDR"
    As long as applications are properly configured with IRSA or PodIdentity, enforcing an IMDS hop limit of `1` should not impact their ability to function, and it will improve the security of your cluster.
