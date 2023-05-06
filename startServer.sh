#!/bin/bash

# Navigate to the directory containing the script
cd "$(dirname "$0")"

# Compile the Java classes
javac -d temp src/main/utility/Validation.java
javac -d temp src/main/utility/Commands.java
javac -d temp src/main/server/ServerConstants.java
javac -d temp src/main/server/ServerClientSessionManager.java
javac -cp ./temp -d temp src/main/server/Server.java src/main/server/ServerClientHandler.java

# Execute the Server program with the given port number
java -cp ./temp a4.src.main.server.Server $1