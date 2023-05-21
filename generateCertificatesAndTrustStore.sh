#!/bin/bash

# Navigate to the directory containing the script
cd "$(dirname "$0")"

# Keytool variables
password=password
validity_days=365
first_last_name=default
org_unit=default
organization=default
city=default
state=default
country_code=default

# Check the user's choice
if [ "$1" == "y" ] || [ "$1" == "Y" ]; then
    choice=y
  else
    read -p "Do you want to generate default certificates? (y/n): " choice
fi

if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
        # Find and remove all .keystore, .cer, and .jks files
        find . -type f \( -name "*.keystore" -o -name "*.cer" -o -name "*.jks" \) -exec rm -f {} \;

        # Generate keystore for client
        generate_keystore_cmd="keytool -genkeypair -alias client -keyalg RSA -keysize 2048 -validity $validity_days -keystore src/main/client/resource/client.keystore -storepass $password"
        generate_keystore_cmd+=" -dname \"CN=$first_last_name, OU=$org_unit, O=$organization, L=$city, ST=$state, C=$country_code\""
        eval $generate_keystore_cmd
        keytool -exportcert -alias client -file src/main/client/resource/client.cer -keystore src/main/client/resource/client.keystore -storepass $password

        # Generate keystore for server
        generate_keystore_cmd="keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity $validity_days -keystore src/main/server/resource/server.keystore -storepass $password"
        generate_keystore_cmd+=" -dname \"CN=$first_last_name, OU=$org_unit, O=$organization, L=$city, ST=$state, C=$country_code\""
        eval $generate_keystore_cmd
        keytool -exportcert -alias server -file src/main/server/resource/server.cer -keystore src/main/server/resource/server.keystore -storepass $password

        # Generate keystore for trust
        generate_keystore_cmd="keytool -genkeypair -alias truststore -keyalg RSA -keysize 2048 -keystore src/main/resource/truststore.jks -storepass $password"
        generate_keystore_cmd+=" -dname \"CN=$first_last_name, OU=$org_unit, O=$organization, L=$city, ST=$state, C=$country_code\""
        eval $generate_keystore_cmd

        # Import server and client keystores
        yes | keytool -import -alias server -file src/main/server/resource/server.cer -keystore src/main/resource/truststore.jks -storepass $password
        yes | keytool -import -alias client -file src/main/client/resource/client.cer -keystore src/main/resource/truststore.jks -storepass $password

    else
        # Generate keystore for client
        keytool -genkeypair -alias client -keyalg RSA -keysize 2048 -validity $validity_days -keystore src/main/client/resource/client.keystore
        keytool -exportcert -alias client -file src/main/client/resource/client.cer -keystore src/main/client/resource/client.keystore
        
        # Generate keystore for server
        keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity $validity_days -keystore src/main/server/resource/server.keystore
        keytool -exportcert -alias server -file src/main/server/resource/server.cer -keystore src/main/server/resource/server.keystore -storepass $password
        
        # Generate keystore for trust
        keytool -genkeypair -alias truststore -keyalg RSA -keysize 2048 -keystore src/main/resource/truststore.jks

        # Import server and client keystores
        keytool -import -alias server -file src/main/server/resource/server.cer -keystore src/main/resource/truststore.jks
        keytool -import -alias client -file src/main/client/resource/client.cer -keystore src/main/resource/truststore.jks
fi

echo "Certificate and Trust Store generation complete"