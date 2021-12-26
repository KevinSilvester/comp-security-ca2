# AES Encryt/Decrypt Java Application

This application uses AES to encrypt and decrypt a user defined text file (.txt).
Only a valid text file such as the _input.txt_ in the application root directory will be encrypted.

The string in the text file will be read by the application, then encrypted using randomly generated key.
An initial vector byte along with the  encypted string will be written a text file called ciphertext.txt.
The key used to encrypt the string will be either stored in another text file _keystore.txt_ or in a password
protected java key store _keystore.jks_.

The saved key can then be used to decrypt the data in _cipher.txt_ back into plaintext.
The decrypted data will be written to _plaintext.txt_.

*************************************************************

#### Only run the program on the terminal as the Console instance is only suitable for terminal interface

*************************************************************

## Compiler and exection commands
### Compile
```shell
# To compile the source code into bin directory
javac -d bin -cp src src/main/java/org/encrytion/*.java
```

### Execution
```shell
# To run compiled class files in bin directory
java -cp bin org.encryption.App
```

*************************************************************


### All references
- <https://stackoverflow.com/questions/14169661/read-complete-file-without-using-loop-in-java>
- <https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/#:~:text=AES%20is%20block%20cipher%20capable,and%20256%2Dbits%2C%20respectively.>
- <https://stackoverflow.com/questions/18228579/how-to-create-a-secure-random-aes-key-in-java/18229498#18229498>
- <https://www.tutorialspoint.com/java_cryptography/java_cryptography_storing_keys.htm>
- <https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html>
- <https://stackoverflow.com/questions/11536848/keystore-type-which-one-to-use>
- <https://stackoverflow.com/questions/21406884/storing-aes-secret-key-using-keystore-in-java>
- <https://www.youtube.com/watch?v=NRHJ8R8Omx4&list=TLPQMjUxMjIwMjEBbFpGLUV4pw&index=3>
