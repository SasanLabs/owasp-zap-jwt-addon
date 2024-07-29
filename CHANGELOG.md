# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

### Unreleased
 - Upgraded spotless version
 - Added vscode launch.json

### Changed
 - Added checks to not raise alerts in CSS, JavaScript or 404 status code pages.

### [1.0.3] - 2023-01-01
 - Ensure i18n resources are always initialized.
 - Added support for incorrect signature type attack.

### [1.0.2] - 2022-01-17
 - Sonar Fixes.
 - Updated Client side attack to introduce warning if HTTP Header contains JWT.
 - Added support for scanning Authorization Header Issue: #31 
 - Corrected the Fuzzer Panel User interface expansion issue

### [1.0.1] - 2020-12-18
 - Increased the number of requests for High threshold to 18 from 12.
 - Client side configuration alerts will not stop the scanner from scanning server side configurations.
 - Support for validating usage of publicly well known HMac secrets for signing JWT.

## [1.0.0] - 2020-09-03
 
 - First version of JWT Support.
   - Contains scanning rules for basic JWT related vulnerabilities.
   - Contains JWT Fuzzer for fuzzing the JWT's present in the request.
