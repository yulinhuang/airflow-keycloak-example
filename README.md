# airflow-keycloak-example

It's an example project of how to use Keycloak with several data science tools including Apache Airflow and Minio. Everything is dockerized and can be run with a single command.

## Requirements
Have docker and docker-compose installed.

## How to run
1. Clone this repository
2. Run `docker-compose up -d` in the root directory of the project
3. Wait for the containers to start
4. Go to keycloak service http://localhost:8181 and login with the credentials specified in the .env file
5. Go to the data science realm and create a new user
6. The airflow service http://localhost:8080 and the Minio service http://localhost:9000 should be able to login with the credentials of the user created in step 5