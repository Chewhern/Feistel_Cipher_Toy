# Note
This feistel cipher implementation does not have strong PRF or does not have proper PRF with an assumption that the key was randomly generated with the help of a **secret material** and a **nonce** as additional parameters.

# Side Note
This new implementation of weak PRF takes some ideas from DJB's AEAD stream cipher, AES256-GCM, AEAD symmetric encryption algorithms. Technically speaking, I have no idea what the NonceSecret or NonceSecurity or NSec in libsodium's cryptography library is for. However, this implementation of feistel cipher has some extent of non-linearity as there's public constants, nonce and a secret parameter, **SecretMaterial** involved. 

# Installation and OS requirement
Requires Windows to run.

Try to run the application's exe, if you can't run the application's exe, proceed with the instructions
below

Go to this link and install the required components.
https://dotnet.microsoft.com/download/dotnet/5.0

You will need to download 5.0.9 or 5.0.10 **".Net Desktop Runtime"** and install them.\
You will also need to download 5.0.9 or 5.0.10 **"ASP.Net Core Runtime"** and install them.\
