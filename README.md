# Feistel_Cipher_Toy
This application showcase how feistel cipher works as a whole.

## Feistel Cipher Note
The F function in feistel cipher diagram requires cryptographers to use either strong PRF(Pseudo-Random Function) which people can assume it as a good hashing function/algorithm or strong PRP (Pseudo-Random Permutation). However, it's recommended to use AES,ChaCha,Salsa as they have been standardized and well tested. Don't use anything I have written in production code.

## Side Note
This feistel cipher application have not go through linear,differential,non-linear analysis and it will have a lot of cryptography algorithm's vulnerability like time-caching attack and side channel attacks.

It will be best to leave it as it's now and it can be used to further understand linear,differential,non-linear analysis and cryptography algorithm's vulnerability that has been solved(or these attacks have been reduced to the maximum potential) that exists in current standardized symmetric encryption algorithms like AES256, ChaCha20, Salsa20.
