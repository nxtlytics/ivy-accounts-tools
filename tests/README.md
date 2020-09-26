# About the testing environment

We are using [localstack](https://github.com/localstack/localstack/)'s [docker image](https://hub.docker.com/r/localstack/localstack) with a [small script](./localstack/initaws.d/start_orgs.sh) that starts `moto_server` which is what adds the ability to test AWS Organizations.

Besides what is mentioned above, we have a vanilla `localstack` environment, accepts any credentials to authenticate, comes with 24 default regions, each one with a default VPC.

## Related links

- [github/localstack - Use localstack to test AWS Organizations](https://github.com/localstack/localstack/issues/1268)
