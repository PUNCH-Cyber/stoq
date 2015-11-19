#   Copyright 2014-2015 PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    config.vm.box = "ubuntu/trusty64"
    config.vm.provision :shell, inline: "apt-get -yq install git-core"
    config.vm.provision :shell, inline: "cd /vagrant && git clone https://github.com/PUNCH-Cyber/stoq.git"
    config.vm.provision :shell, inline: "cd /vagrant/stoq && bash ./install.sh"

    # RabbitMQ Adminsitration Interface
    config.vm.network "forwarded_port", guest: 15672, host: 15672

        config.vm.provider "virtualbox" do |v|
            v.memory = 1024
            v.cpus = 2
        end
end


