# Rijndael AES 128-bit algorithm. 

Credits to [boppreh](https://github.com/boppreh/aes/) for the Python reference. 
The code contains functionality for encrypting and decrypting a single block using Rijndael's 128-bit encryption algorithm. 

## 1. Run the tests
- Build the container: `docker build -t rijndael .`
- Run the test-runner: `docker run -it --rm --name test-runner rijndael pytest -v`

```
// all together
docker build -t rijndael . && docker run -it --rm --name test-runner rijndael pytest -v
```

## 2. Folder structure: 
```
RIJNDAEL-AES
│   readme.md
│   Dockerfile.txt    
│
└───dist // output / compiled c code 
│
└───src 
│   │   lookup_table.c 
│   │   main.c
│   │   rijndael.c
│   │   rijndael.c
│   │
│   └───hall_of_fame // inefficient but cool code
│   
└───tests
│   │
│   └───aes_ref // submodule, AES in Python for reference
│   │
│   └───suite_x // test suite with test_y.py files
│   │
│   └───util // loads c code and formatters 
│   │
│   └───wrappers // wrappers for fixtures and GC.
```