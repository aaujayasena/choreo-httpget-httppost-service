# Risk Assessment Service

This is a simple Ballerina service that simulates assessing the risk of an IP address based on its geolocation. The service checks if the IP address belongs to a specific country and returns a risk assessment. Note: This service simulates the behavior described above and always returns a response indicating that there is a risk identified, regardless of the actual IP address or location

## Prerequisites

- [Ballerina](https://ballerina.io/) installed on your machine.

## Project Structure

├── Ballerina.toml
├── main.bal
└── README.md


- `main.bal`: Contains the Ballerina service implementation.
- `Ballerina.toml`: Configuration file for the project.
- `README.md`: This file.

## Configuration

- Open the `Ballerina.toml` file (if exists) or use the `ballerina` command to run the service with the configurations:

```toml
[build-options]
observabilityIncluded = true

[dependencies]

[configurable]
issuer = "<issuer of the token>";
requiredScopes = "<required scopes to call the api>";

Note: The `requiredScopes` in this configuration are the same scopes that are set up in the end-to-end (E2E) test configuration. Ensure that these scopes match those defined in your E2E tests to avoid authorization issues.
