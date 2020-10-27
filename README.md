# GoLab
How can you test the lab:
1- Clone this repo.
2- Build the docker image: docker build -t golab .
3- Run the docker image container:  docker run -p 8080:8080 golab

Consume the rest api using the tool that you prefer:
To encrypt a string:
curl -X POST -H 'Content-Type: application/json' -d "{\"Content\": \"TestMessage\"}" http://localhost:8080/api/encrypt
Response:
{
    "status": "201",
    "message": "encrypt called",
    "result": "mTXAaO3YVuBxVyk="
}

To decrypt a string:
curl -X POST -H 'Content-Type: application/json' -d "{\"Content\": \"TestMessage\"}" http://localhost:8080/api/decrypt
Response
{
    "status": "201",
    "message": "decrypt called",
    "result": "TestMessage"
}
