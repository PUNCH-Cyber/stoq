/*
   Copyright 2014-2016 PUNCH Cyber Analytics Group

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

rule test_dispatch_rule_single
{
    meta:
        plugin = "carver:test_carver"
        save = "True"
    strings:
        $test = "single-test"
    condition:
        any of them
}

rule test_dispatch_rule_multi
{
    meta:
        plugin = "carver:test_carver,decoder:test_decoder,extractor:test_extractor"
        save = "True"
    strings:
        $test = "multi-test"
    condition:
        any of them
}

rule test_dispatch_rule_multi_with_space
{
    meta:
        plugin = "carver:test_carver, decoder:test_decoder"
        save = "True"
    strings:
        $test = "multi-test-with-space"
    condition:
        any of them
}

rule test_dispatch_rule_invalid_syntax
{
    meta:
        plugin = "this is an invalid syntax"
        save = "True"
    strings:
        $test = "multi-test-invalid-syntax"
    condition:
        any of them
}