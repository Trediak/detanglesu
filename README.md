# detanglesu

**detanglesu is a ruby utility designed to parse sudoers files**

## Current Features:

1. Parses sudoers file (likely not all features of sudo are included yet)
2. Access placed in hash using references to a lookup table

## How to works

1. Create new DetangleSu::Parser object
2. Object initialization kicks off parsing of aliases and user specification pre-processing.  Aliases
   are placed in hash for later reference and added to lookup table.  User specifications are placed
   in an array for later processing.
3. When pre-processing is complete, user specification processing begins by creating the access hash
   using references to the lookup table.

## Usage:
require 'detanglesu'

DetangleSu::Parser.new(:filepath => 'pathtosudoersfile', :filename => 'sudoersfilename')

## Planned enhancements
(in no particular order)

* Create module to query access
* Create method to reassemble access into generic aliases
* Convert this to a gem which will also provide command-line functionality
* Add testing

## Copyright

Copyright (c) 2014 Kevin Zittel. See LICENSE.md for
further details.
