# James Daly Evervault Submission

This is an implementation of a basic encryption service written in Rust. To run the service the user must have a copy of
the Cargo dependency manager and the rust tool chain. To start the service simply type 
```
cargo run
```
This will start the service at http://localhost:8080

This service has 3 endpoints:
```
http://localhost:8080/encrypt
http://localhost:8080/decrypt
http://localhost:8080/sign
```
These all accept arbitrary json and fulfill the requirements as outlined. Here are calls to verify this:
```
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"username":"shane","password":"really_good_password"}' \
  http://localhost:8080/encrypt

curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"password":"5/83/217/18/106/83/193/187/152/212/64/237/65/231/63/205/235/114/112/231/246","username":"5/79/198/15/46/216/184/21/217/208/180/222/15/113/19/206/156/119/235/172/99/33/184/243/67/3"}' \
  http://localhost:8080/decrypt

curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"username":"shane","password":"really_good_password"}' \
  http://localhost:8080/sign
```

## Design Choices
* For a web framework I chose Actix-Web as it's both lightweight and multi threaded meaning it is perfect for a web service
which is computationally heavy but has no external dependence.  
* I went with a 256 bit AES cipher as it was one of the more well known cryptographic ciphers and it's rust implementation
is quite mature.
* All encrypted fields are returned as a series of 8 bit numbers. This is because AES uses the full buffer space and
some of the characters when decoded are illegal in json.
* For creating a signature I used Rust's built in hash functions for convenience.

### Shortcomings

I did not complete the verify endpoint as I ran out of time. I could not figure out a way to ingest arbitrary json and
determine whether it is encrypted or not. I'd like to hear your ideas. 







