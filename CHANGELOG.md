# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

### Added
 - Increased the number of requests for High threshold to 18 from 12.
 - Client side configuration alerts will not stop the scanner from scanning server side configurations.
 - Support for validating usage of publicly well known HMac secrets for signing JWT.

## [1.0.0] - 2020-09-03
 
 - First version of JWT Support.
   - Contains scanning rules for basic JWT related vulnerabilities.
   - Contains JWT Fuzzer for fuzzing the JWT's present in the request.
