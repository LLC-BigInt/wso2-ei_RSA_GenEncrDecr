# Project of WSO2 Enterprise Integrator implement works with RSA KeyPairGenerator & Encrypt Decrypt

##RSAGenEncrDecrMediator have a 2 Java Core Class:
1. RSAKeyPairGenerator - can generate RSA Keys (public & private) in dyrectory
2. RSAKeyEncrDecr - can encrypt & decrypt string (with read public & private keys from dyrectory)

##RSAGenEncrDecrMediator tested on jdk 8.0.1 & jdk 11.0.1

## /service - example service for use
## /service/generate - method of service starting to generate KeyPair
## /service/encrypte - method of service starting to ecryption of string
## /service/decrypte - method of service starting to decryption of string

## Properties of /service
1. fpathPublic - Path of public key
2. fpathPrivate - Path of private key
3. sizeKeyS - Size of Keys
4. strExec - String for encrypt & decrypt
5. typeExec - Type of operation (must have encrypte or decrypte)

respond (result) of /service is JSON {"result":"$1"}