# Run the container
- Build the container: `docker build -t rijndael .`
- Run the test-runner: `docker run -it --rm --name test-runner rijndael pytest -v`

docker build -t rijndael . && docker run -it --rm --name test-runner rijndael pytest -v