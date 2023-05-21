#!/bin/bash

# Navigate to the directory containing the script
cd "$(dirname "$0")"

# Compile the Java classes
javac -d temp src/main/utility/Validation.java
javac -d temp src/main/utility/Commands.java
javac -d temp src/main/utility/SecurityUtilityException.java
javac -cp ./temp -d temp src/main/utility/SecurityUtility.java
javac -d temp src/main/server/ServerConstants.java
javac -d temp src/main/server/ServerClientSessionManager.java
javac -cp ./temp -d temp src/main/server/Server.java src/main/server/ServerClientHandler.java

# Prompt the user
read -p "Do you want to generate default certificates? (y/n): " choice

# Check the user's choice
if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
  # Execute the script
  ./generateCertificatesAndTrustStore.sh $choice
fi

# Execute the Server program with the given port number
java -cp ./temp a4.src.main.server.Server $1