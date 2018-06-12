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

rule simple_rule
{
    meta:
        plugin = "simple_worker"
    strings:
        $test = "The quick brown fox"
    condition:
        any of them
}

rule similar_simple_rule
{
    meta:
        plugin = "simple_worker"
        save = "False"
    strings:
        $test = "brown fox"
    condition:
        any of them
}

rule multi_plugin_rule
{
    meta:
        plugin = "dummy_worker,simple_worker"
    strings:
        $test = "multi-plugin-content"
    condition:
        any of them
}

rule multi_plugin_rule_with_space
{
    meta:
        plugin = "dummy_worker, simple_worker"
    strings:
        $test = "again-multi-plugin-space-content"
    condition:
        any of them
}
