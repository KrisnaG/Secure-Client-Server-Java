#!/bin/bash

# Navigate to the directory containing the script
cd "$(dirname "$0")"

# Compile the Java classes
javac -d temp src/main/utility/Validation.java
javac -d temp src/main/utility/Commands.java
javac -d temp src/main/utility/SecurityUtilityException.java
javac -cp ./temp -d temp src/main/utility/SecurityUtility.java
javac -d temp src/main/client/ClientConstants.java
javac -d temp src/main/client/ClientException.java
javac -cp ./temp -d temp src/main/client/ClientUserHandling.java
javac -cp ./temp -d temp src/main/client/Client.java

# Execute the Client program with the specified host name and port number
java -cp ./temp a4.src.main.client.Client $1 $2