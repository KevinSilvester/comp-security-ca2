# MENU SYSTEM
- Encrypt a file
- Decrypt a file
- Quit Application
- Input validation
- Rerun menu after process


## ENCRYPT FILE
- Input validation
- Rerun menu after process
- Enter file name \ file not found exception
- Generate random key (MUST TALK ABOUT)
- Print generated
- Store key for future use
- Options for storing method


## DECRYPT FILE
- Input validation
- Rerun menu after process
- Enter file name
- Enter a valid key (LEAVE KEY STORE FOR LAST)
   - copy and paste key
   - read key frm file
   - read key from key store


****************************************************************************


### Encryption Process
1. User enters the file name
2. Search for file. If not found throw error and catch in menu
3. Generate new random key with KeyGenerator.
   - Use KeyGenerator to gererate new SecretKey object, 
   - Use SecretKeyFactory to generate new SecretKey object from a plaintext key material.
4. Encrypt the 'input' plaintext into ciphertext using Cipher object.
