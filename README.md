# swift_d-zkp-- A Framework for Generic Hybrid Three-Party Computation, with Verification via a Distributed Zero Knowledge Proof. 

This software is an extension of the Motion2NX [https://github.com/encryptogroup/MOTION2NX]. MOTION2NX supports 2 party in a honest majority setting. swift_d-zkp supports 3 parties with at most 1 maliciously corrupted adversary.  

I implemented <br />
-SWIFT ( security with abort) [https://eprint.iacr.org/2020/592]  <br /> 
-Distributed Zero Knowledge Proof [https://dl.acm.org/doi/abs/10.1145/3319535.3363227 ] using the NTL library [https://libntl.org/] <br />
-a three party shared correlated randomness <br />

Compared to the original MOTIO2NX codebase, we made architectural improvements
to increase flexibility and performance of the framework. 
No changes need to be made from the protocol level Or from the verification of the protocol level. One can plug in any circuit of choice from the application layer. 

This code is provided as a experimental implementation for testing purposes and
should not be used in a productive environment. We cannot guarantee security
and correctness.


## Build Instructions

Kindly refer to the readme of MOTION2NX. 

## AN example run of the Millionaire's problem would look something like the below

/bin/millionaires_problem --my-id 0 --party 0,::1,7271 --party 1,::1,7272 --party 2,::1,7273 --arithmetic-protocol beavy --boolean-protocol beavy --repetitions 1 --input-value 20

./bin/millionaires_problem --my-id 1 --party 0,::1,7271 --party 1,::1,7272 --party 2,::1,7273 --arithmetic-protocol beavy --boolean-protocol beavy --repetitions 1 --input-value 30

./bin/millionaires_problem --my-id 2 --party 0,::1,7271 --party 1,::1,7272 --party 2,::1,7273 --arithmetic-protocol beavy --boolean-protocol beavy --repetitions 1 --input-value 0

//along with the correctness of swift  <br />
//and ACCEPT or ABORT statement from the DIZK protocol, the stats would look something like below in each of the 3 parties

Heres is the link to the screenshot of the end stats https://drive.google.com/file/d/1MLQWqvrNpRBZECmi-cRBFjfj-FIbBL0F/view?usp=sharing. 


