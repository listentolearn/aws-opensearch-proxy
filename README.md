# aws-opensearch-proxy

This repository consists of lambda function code in python 3.8 that enables you to connect to AWS Opensearch domain which is deployed within a VPC.

## Things to do

1. Add two environment variables to the lambda function.
    1. HOST - OpenSearch domain endpoint host
    2. API_STAGE - API gateway stage name
2. Add a new role with the policy (use the contents of the proxy_lambda_policy.json) and attach it as the execution role of the lambda. Replace the <accountId> with actual account id within the file.
3. The zip file opensearch_proxy_lambda.zip contains the lambda function along with the dependant python 3.8 packages which can be uploaded to the lambda function code. If you are using a different python version, please use the corresponding packages.
