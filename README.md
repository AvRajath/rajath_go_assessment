# Rajath Go assessment
This repository contains a Go program to scanner and detect MySQL running on a port on a host.

## Prerequisites
Go ~1.20.2

## Installation
Clone the repository to your local machine:

```
git clone https://github.com/AvRajath/rajath-go-assessment.git
```

## Usage
To run the program, use the following command:

```
./bin/rajath_go_assessment hostname port_number
```
Replace hostname and port_number with the actual hostname and port number you want to connect to.

For example:

```
./bin/rajath_go_assessment localhost 3306
```

## Sample Output

```
----------------------------------------------------------------------
localhost:3306
Protocol version: 10
Server version: 8.0.32
Connection ID: 25
Auth Plugin Data Len: 21
Authentication plugin name: caching_sha2_password
Status flags: 2
Capability flag: 3758096383
Character set: 255
```
