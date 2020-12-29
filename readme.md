# Secure File Transfer Over Unsecure Network 

## TODO

* **Client** should get Public Key
* **Client** generate Random Session Key
* **Client** send Session Key to **Server**
* **Client** send size of block to **Server**
* **Client** send blocks to **Server**
* **Client** has a trick for not to send some blocks


* **Server** generate Public Private Key
* **Server** get Session Key from **Client**
* **Server** get information from **Client**
* **Server** get text file as blocks from **Client**
* **Server** check blog according to information then if necessary request to **Client** again