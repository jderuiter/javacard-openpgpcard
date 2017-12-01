# Java Card OpenPGP Card

This is a Java Card implementation of the OpenPGP smart card specifications.

# Building

`git submodule update --init --recursive`

`ant`

# Testing

`ant test`

# Installing

This can easily be done using GlobalPlatformPro (https://github.com/martinpaljak/GlobalPlatformPro):

`java -jar gp.jar -install openpgpcard.cap`
